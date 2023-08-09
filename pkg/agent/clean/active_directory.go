/*
Look for any active directory users with a GUID type principal.
Convert these users to a distinguished name instead.
*/

package clean

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/activedirectory"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/providers/common/ldap"
	"github.com/rancher/rancher/pkg/auth/tokens"
	v3client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	migrateAdUserOperation    = "migrate-ad-user"
	identifyAdUserOperation   = "identify-ad-users"
	migrateTokensOperation    = "migrate-ad-tokens"
	migrateCrtbsOperation     = "migrate-ad-crtbs"
	migratePrtbsOperation     = "migrate-ad-prtbs"
	activeDirectoryPrefix     = "activedirectory_user://"
	localPrefix               = "local://"
	adGUIDMigrationLabel      = "ad-guid-migration"
	adGUIDMigrationAnnotation = "ad-guid-migration-data"
	migratedLabelValue        = "migrated"
	migrationPreviousName     = "ad-guid-previous-name"
	AttributeObjectClass      = "objectClass"
	AttributeObjectGUID       = "objectGUID"
)

type migrateUserWorkUnit struct {
	distinguishedName    string
	guid                 string
	originalUser         *v3.User
	duplicateUsers       []*v3.User
	guidCRTBs            []v3.ClusterRoleTemplateBinding
	duplicateLocalCRTBs  []v3.ClusterRoleTemplateBinding
	guidPRTBs            []v3.ProjectRoleTemplateBinding
	duplicateLocalPRTBs  []v3.ProjectRoleTemplateBinding
	guidTokens           []v3.Token
	duplicateLocalTokens []v3.Token
}

type missingUserWorkUnit struct {
	guid           string
	originalUser   *v3.User
	duplicateUsers []*v3.User
}

type skippedUserWorkUnit struct {
	guid         string
	originalUser *v3.User
}

type LdapErrorNotFound struct{}

// Error provides a string representation of an LdapErrorNotFound
func (e LdapErrorNotFound) Error() string {
	return "ldap query returned no results"
}

// LdapFoundDuplicateGuid indicates either a configuration error or
// a corruption on the Active Directory side. In theory it should never
// be possible when talking to a real Active Directory server, but just
// in case we detect and handle it anyway.
type LdapFoundDuplicateGuid struct{}

// Error provides a string representation of an LdapErrorNotFound
func (e LdapFoundDuplicateGuid) Error() string {
	return "ldap query returned multiple users for the same GUID"
}

type LdapConnectionPermanentlyFailed struct{}

// Error provides a string representation of an LdapConnectionPermanentlyFailed
func (e LdapConnectionPermanentlyFailed) Error() string {
	return "ldap search failed to connect after exhausting maximum retry attempts"
}

func scaledContext(restConfig *restclient.Config) (*config.ScaledContext, error) {
	sc, err := config.NewScaledContext(*restConfig, nil)
	if err != nil {
		logrus.Errorf("[%v] failed to create scaledContext: %v", migrateAdUserOperation, err)
		return nil, err
	}

	ctx := context.Background()
	err = sc.Start(ctx)
	if err != nil {
		logrus.Errorf("[%v] failed to start scaled context: %v", migrateAdUserOperation, err)
		return nil, err
	}

	return sc, nil
}

func adConfiguration(sc *config.ScaledContext) (*v3.ActiveDirectoryConfig, error) {
	authConfigs := sc.Management.AuthConfigs("")
	secrets := sc.Core.Secrets("")

	authConfigObj, err := authConfigs.ObjectClient().UnstructuredClient().Get("activedirectory", metav1.GetOptions{})
	if err != nil {
		logrus.Errorf("[%v] failed to obtain activedirecotry authConfigObj: %v", migrateAdUserOperation, err)
		return nil, err
	}

	u, ok := authConfigObj.(runtime.Unstructured)
	if !ok {
		logrus.Errorf("[%v] failed to retrieve ActiveDirectoryConfig, cannot read k8s Unstructured data %v", migrateAdUserOperation, err)
		return nil, err
	}
	storedADConfigMap := u.UnstructuredContent()

	storedADConfig := &v3.ActiveDirectoryConfig{}
	err = mapstructure.Decode(storedADConfigMap, storedADConfig)
	if err != nil {
		logrus.Debugf("[%v] errors while decoding stored AD config: %v", migrateAdUserOperation, err)
	}

	metadataMap, ok := storedADConfigMap["metadata"].(map[string]interface{})
	if !ok {
		logrus.Errorf("[%v] failed to retrieve ActiveDirectoryConfig, (second step), cannot read k8s Unstructured data %v", migrateAdUserOperation, err)
	}

	typemeta := &metav1.ObjectMeta{}
	err = mapstructure.Decode(metadataMap, typemeta)
	if err != nil {
		logrus.Debugf("[%v] errors while decoding typemeta: %v", migrateAdUserOperation, err)
	}

	storedADConfig.ObjectMeta = *typemeta

	logrus.Debugf("[%v] Should in theory have ActiveDirectory config data? Let's check!", migrateAdUserOperation)
	logrus.Debugf("[%v] AD Service Account User: %v", migrateAdUserOperation, storedADConfig.ServiceAccountUsername)

	if storedADConfig.ServiceAccountPassword != "" {
		value, err := common.ReadFromSecret(secrets, storedADConfig.ServiceAccountPassword,
			strings.ToLower(v3client.ActiveDirectoryConfigFieldServiceAccountPassword))
		if err != nil {
			return nil, err
		}
		storedADConfig.ServiceAccountPassword = value
	}

	return storedADConfig, nil
}

func newCAPool(cert string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	pool.AppendCertsFromPEM([]byte(cert))
	return pool, nil
}

func ldapConnection(config *v3.ActiveDirectoryConfig) (*ldapv3.Conn, error) {
	caPool, err := newCAPool(config.Certificate)
	if err != nil {
		return nil, fmt.Errorf("unable to create caPool: %v", err)
	}

	servers := config.Servers
	TLS := config.TLS
	port := config.Port
	connectionTimeout := config.ConnectionTimeout
	startTLS := config.StartTLS

	ldapConn, err := ldap.NewLDAPConn(servers, TLS, startTLS, port, connectionTimeout, caPool)
	if err != nil {
		return nil, err
	}

	serviceAccountUsername := ldap.GetUserExternalID(config.ServiceAccountUsername, config.DefaultLoginDomain)
	err = ldapConn.Bind(serviceAccountUsername, config.ServiceAccountPassword)
	if err != nil {
		return nil, err
	}
	return ldapConn, nil
}

// EscapeUUID will take a UUID string in string form and will add backslashes to every 2nd character.
// The returned result is the string that needs to be added to the LDAP filter to properly filter
// by objectGUID, which is stored as binary data.
func escapeUUID(s string) string {
	var buffer bytes.Buffer
	var n1 = 1
	var l1 = len(s) - 1
	buffer.WriteRune('\\')
	for i, r := range s {
		buffer.WriteRune(r)
		if i%2 == n1 && i != l1 {
			buffer.WriteRune('\\')
		}
	}
	return buffer.String()
}

func findDistinguishedName(guid string, lConn *ldapv3.Conn, adConfig *v3.ActiveDirectoryConfig) (string, error) {
	query := fmt.Sprintf("(&(%v=%v)(%v=%v))", AttributeObjectClass, adConfig.UserObjectClass, AttributeObjectGUID, escapeUUID(guid))
	search := ldapv3.NewSearchRequest(adConfig.UserSearchBase, ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases,
		0, 0, false,
		query, ldap.GetUserSearchAttributes("memberOf", "objectClass", adConfig), nil)

	result, err := lConn.Search(search)
	if err != nil {
		return "", err
	}

	if len(result.Entries) < 1 {
		return "", LdapErrorNotFound{}
	} else if len(result.Entries) > 1 {
		return "", LdapFoundDuplicateGuid{}
	}

	entry := result.Entries[0]

	return entry.DN, nil
}

func findDistinguishedNameWithRetries(guid string, lConn *ldapv3.Conn, adConfig *v3.ActiveDirectoryConfig) (string, error) {
	const maxRetries = 5
	const retryDelay = 10 * time.Second

	for retry := 0; retry < maxRetries; retry++ {
		distinguishedName, err := findDistinguishedName(guid, lConn, adConfig)
		if err == nil || errors.Is(err, LdapErrorNotFound{}) || errors.Is(err, LdapFoundDuplicateGuid{}) {
			return distinguishedName, err
		}
		logrus.Warnf("[%v] LDAP connection failed: '%v', retrying in %v...", migrateAdUserOperation, err, retryDelay.Seconds())
		time.Sleep(retryDelay)
		// We don't know why the search failed, it might indicate that the connection has gone stale. Let's
		// try to re-establish it to be safe
		lConn.Close()
		lConn, err = ldapConnection(adConfig)
		// If that also fails, we're definitely having a rough time of things.
		if err != nil {
			return "", LdapConnectionPermanentlyFailed{}
		}
	}
	return "", LdapConnectionPermanentlyFailed{}
}

// prepareClientContexts sets up a scaled context with the ability to read users and AD configuration data
func prepareClientContexts(clientConfig *restclient.Config) (*config.ScaledContext, *v3.ActiveDirectoryConfig, error) {
	var restConfig *restclient.Config
	var err error
	if clientConfig != nil {
		restConfig = clientConfig
	} else {
		restConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			logrus.Errorf("[%v] failed to build the cluster config: %v", migrateAdUserOperation, err)
			return nil, nil, err
		}
	}

	sc, err := scaledContext(restConfig)
	if err != nil {
		return nil, nil, err
	}
	adConfig, err := adConfiguration(sc)
	if err != nil {
		return nil, nil, err
	}

	return sc, adConfig, nil
}

// UnmigrateAdGUIDUsersOnce will ensure that the migration script will run only once.  cycle through all users, ctrb, ptrb, tokens and migrate them to an
// appropriate DN-based PrincipalID.
func UnmigrateAdGUIDUsersOnce(sc *config.ScaledContext) error {
	migrationConfigMap, _ := sc.Core.ConfigMaps(activedirectory.StatusConfigMapNamespace).GetNamespaced(activedirectory.StatusConfigMapNamespace, activedirectory.StatusConfigMapName, metav1.GetOptions{})
	if migrationConfigMap != nil {
		migrationStatus := migrationConfigMap.Data[activedirectory.StatusMigrationField]
		switch migrationStatus {
		case activedirectory.StatusMigrationFinished:
			logrus.Debugf("[%v] ad-guid migration has already been completed, refusing to run again at startup", migrateAdUserOperation)
			return nil
		}
	}
	return UnmigrateAdGUIDUsers(&sc.RESTConfig, false, false)
}

// UnmigrateAdGUIDUsers will cycle through all users, ctrb, ptrb, tokens and migrate them to an
// appropriate DN-based PrincipalID.
func UnmigrateAdGUIDUsers(clientConfig *restclient.Config, dryRun bool, deleteMissingUsers bool) error {
	if dryRun {
		logrus.Infof("[%v] dryRun is true, no objects will be deleted/modified", migrateAdUserOperation)
		deleteMissingUsers = false
	} else if deleteMissingUsers {
		logrus.Infof("[%v] deleteMissingUsers is true, GUID-based users not present in Active Directory will be deleted", migrateAdUserOperation)
	}

	sc, adConfig, err := prepareClientContexts(clientConfig)
	if err != nil {
		return err
	}

	migrationConfigMap, _ := sc.Core.ConfigMaps(activedirectory.StatusConfigMapNamespace).GetNamespaced(activedirectory.StatusConfigMapNamespace, activedirectory.StatusConfigMapName, metav1.GetOptions{})
	if migrationConfigMap != nil {
		migrationStatus := migrationConfigMap.Data[activedirectory.StatusMigrationField]
		switch migrationStatus {
		case activedirectory.StatusMigrationRunning:
			logrus.Infof("[%v] ad-guid migration is currently running, refusing to run again concurrently", migrateAdUserOperation)
			return nil
		}
	}

	// We'll share this lConn for all lookups to hopefully speed things along
	lConn, err := ldapConnection(adConfig)
	if err != nil {
		return err
	}
	defer lConn.Close()

	err = updateMigrationStatus(sc, activedirectory.StatusMigrationField, activedirectory.StatusMigrationRunning)
	if err != nil {
		return fmt.Errorf("unable to update migration status configmap: %v", err)
	}

	users, err := sc.Management.Users("").List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to fetch user list: %v", err)
	}

	usersToMigrate, missingUsers, skippedUsers := identifyMigrationWorkUnits(users, lConn, adConfig)
	err = collectTokens(&usersToMigrate, sc)
	if err != nil {
		return err
	}
	err = collectCRTBs(&usersToMigrate, sc)
	if err != nil {
		return err
	}
	err = collectPRTBs(&usersToMigrate, sc)
	if err != nil {
		return err
	}

	for _, user := range skippedUsers {
		logrus.Errorf("[%v] unable to migrate user '%v' due to a connection failure; this user will be skipped", migrateAdUserOperation, user.originalUser.Name)
	}
	for _, missingUser := range missingUsers {
		if deleteMissingUsers && !dryRun {
			logrus.Infof("[%v] user '%v' with GUID '%v' does not seem to exist in Active Directory. deleteMissingUsers is true, proceeding to delete this user permanently", migrateAdUserOperation, missingUser.originalUser.Name, missingUser.guid)
			err = sc.Management.Users("").Delete(missingUser.originalUser.Name, &metav1.DeleteOptions{})
			if err != nil {
				logrus.Errorf("[%v] failed to delete missing user '%v' with: %v", migrateAdUserOperation, missingUser.originalUser.Name, err)
			}
		} else {
			logrus.Errorf("[%v] User '%v' with GUID '%v' does not seem to exist in Active Directory. this user will be skipped", migrateAdUserOperation, missingUser.originalUser.Name, missingUser.guid)
		}
	}

	for _, userToMigrate := range usersToMigrate {
		// If any of the binding replacements fail, then the resulting rancher state for this user is inconsistent
		//   and we should NOT attempt to modify the user or delete any of its duplicates. This situation is unusual
		//   and must be investigated by the local admin.
		err := migrateTokens(&userToMigrate, sc, dryRun)
		if err != nil {
			logrus.Errorf("[%v] unable to migrate tokens for user '%v': %v", migrateAdUserOperation, userToMigrate.originalUser.Name, err)
			continue
		}
		err = migrateCRTBs(&userToMigrate, sc, dryRun)
		if err != nil {
			logrus.Errorf("[%v] unable to migrate CRTBs for user '%v': %v", migrateAdUserOperation, userToMigrate.originalUser.Name, err)
			continue
		}
		err = migratePRTBs(&userToMigrate, sc, dryRun)
		if err != nil {
			logrus.Errorf("[%v] unable to migrate PRTBs for user '%v': %v", migrateAdUserOperation, userToMigrate.originalUser.Name, err)
			continue
		}
		replaceGUIDPrincipalWithDn(userToMigrate.originalUser, userToMigrate.distinguishedName, userToMigrate.guid, dryRun)

		if dryRun {
			describePlannedChanges(userToMigrate)
		} else {
			err = deleteDuplicateUsers(userToMigrate, sc)
			if err != nil {
				updateModifiedUser(userToMigrate, sc)
			}
		}
	}

	err = updateMigrationStatus(sc, activedirectory.StatusMigrationField, activedirectory.StatusMigrationFinished)
	if err != nil {
		return fmt.Errorf("unable to update migration status configmap: %v", err)
	}

	return nil
}

func describePlannedChanges(workunit migrateUserWorkUnit) {
	logrus.Infof("DRY RUN: changes to user '%v' have NOT been saved.", workunit.originalUser.Name)
	if len(workunit.duplicateUsers) > 0 {
		logrus.Infof("[%v] DRY RUN: duplicate users were identified", migrateAdUserOperation)
		for _, duplicateUser := range workunit.duplicateUsers {
			logrus.Infof("[%v] DRY RUN: would DELETE user %v", migrateAdUserOperation, duplicateUser.Name)
		}
	}
}

func deleteDuplicateUsers(workunit migrateUserWorkUnit, sc *config.ScaledContext) error {
	for _, duplicateUser := range workunit.duplicateUsers {
		err := sc.Management.Users("").Delete(duplicateUser.Name, &metav1.DeleteOptions{})
		if err != nil {
			logrus.Errorf("[%v] failed to delete dupliate user '%v' with: %v", migrateAdUserOperation, workunit.originalUser.Name, err)
			// If the duplicate deletion has failed for some reason, it is NOT safe to save the modified user, as
			// this may result in a duplicate AD principal ID. Notify and skip.

			logrus.Errorf("[%v] cannot safely save modifications to user %v, skipping", migrateAdUserOperation, workunit.originalUser.Name)
			return errors.Errorf("failed to delete duplicate users")
		}
		logrus.Infof("[%v] deleted duplicate user %v", migrateAdUserOperation, duplicateUser.Name)
	}
	return nil
}

func updateModifiedUser(workunit migrateUserWorkUnit, sc *config.ScaledContext) {
	workunit.originalUser.Annotations[adGUIDMigrationAnnotation] = workunit.guid
	workunit.originalUser.Labels[adGUIDMigrationLabel] = migratedLabelValue
	_, err := sc.Management.Users("").Update(workunit.originalUser)
	if err != nil {
		logrus.Errorf("[%v] failed to save modified user '%v' with: %v", migrateAdUserOperation, workunit.originalUser.Name, err)
	}
	logrus.Infof("[%v] user %v was successfully migrated", migrateAdUserOperation, workunit.originalUser.Name)
}

// identifyMigrationWorkUnits locates ActiveDirectory users with GUID and DN based principal IDs and sorts them
// into work units based on whether those users can be located in the upstream Active Directory provider. Specifically:
//
//	usersToMigrate contains GUID-based original users and any duplicates (GUID or DN based) that we wish to merge
//	missingUsers contains GUID-based users who could not be found in Active Directory
//	skippedUsers contains GUID-based users that could not be processed, usually due to an LDAP connection failure
func identifyMigrationWorkUnits(users *v3.UserList, lConn *ldapv3.Conn, adConfig *v3.ActiveDirectoryConfig) (
	[]migrateUserWorkUnit, []missingUserWorkUnit, []skippedUserWorkUnit) {
	// Note: we *could* make the ldap connection on the spot here, but we're accepting it as a parameter specifically
	// so that this function is easier to test. This setup allows us to mock the ldap connection and thus more easily
	// test unusual Active Directory responses to our searches.

	var usersToMigrate []migrateUserWorkUnit
	var missingUsers []missingUserWorkUnit
	var skippedUsers []skippedUserWorkUnit

	// These assist with quickly identifying duplicates, so we don't have to scan the whole structure each time.
	// We key on guid/dn, and the value is the index of that work unit in the associated table
	knownGUIDWorkUnits := map[string]int{}
	knownGUIDMissingUnits := map[string]int{}
	knownDnWorkUnits := map[string]int{}

	// Now we'll make two passes over the list of all users. First we need to identify any GUID based users, and
	// sort them into "found" and "not found" lists. At this stage we might have GUID-based duplicates, and we'll
	// detect and sort those accordingly
	ldapPermanentlyFailed := false
	logrus.Debugf("[%v] locating GUID-based Active Directory users", identifyAdUserOperation)
	for _, user := range users.Items {
		if !isAdUser(&user) {
			logrus.Debugf("[%v] user '%v' has no AD principals, skipping", identifyAdUserOperation, user.Name)
			continue
		}
		principalID := adPrincipalID(&user)
		logrus.Debugf("[%v] processing AD User '%v' with principal ID: '%v'", identifyAdUserOperation, user.Name, principalID)
		if !isGUID(principalID) {
			logrus.Debugf("[%v] '%v' does not appear to be a GUID-based principal ID, taking no action", identifyAdUserOperation, principalID)
			continue
		}
		guid, err := getExternalID(principalID)

		if err != nil {
			// This really shouldn't be possible to hit, since isGuid will fail to parse anything that would
			// cause getExternalID to choke on the input, but for maximum safety we'll handle it anyway.
			logrus.Errorf("[%v] failed to extract GUID from principal '%v', cannot process user: '%v'", identifyAdUserOperation, err, user.Name)
			continue
		}
		// If our LDAP connection has gone sour, we still need to log this user for reporting
		if ldapPermanentlyFailed {
			skippedUsers = append(skippedUsers, skippedUserWorkUnit{guid: guid, originalUser: user.DeepCopy()})
		} else {
			// Check for guid-based duplicates here. If we find one, we don't need to perform an other LDAP lookup.
			if i, exists := knownGUIDWorkUnits[guid]; exists {
				logrus.Debugf("[%v] user %v is GUID-based (%v) and a duplicate of %v",
					identifyAdUserOperation, user.Name, guid, usersToMigrate[i].originalUser.Name)
				// Make sure the oldest duplicate user is selected as the original
				if usersToMigrate[i].originalUser.CreationTimestamp.Time.After(user.CreationTimestamp.Time) {
					usersToMigrate[i].duplicateUsers = append(usersToMigrate[i].duplicateUsers, usersToMigrate[i].originalUser)
					usersToMigrate[i].originalUser = user.DeepCopy()
				} else {
					usersToMigrate[i].duplicateUsers = append(usersToMigrate[i].duplicateUsers, user.DeepCopy())
				}
				continue
			}
			if i, exists := knownGUIDMissingUnits[guid]; exists {
				logrus.Debugf("[%v] user %v is GUID-based (%v) and a duplicate of %v which is known to be missing",
					identifyAdUserOperation, user.Name, guid, missingUsers[i].originalUser.Name)
				// We're less picky about the age of the oldest user here, because we aren't going to deduplicate these
				missingUsers[i].duplicateUsers = append(missingUsers[i].duplicateUsers, user.DeepCopy())
				continue
			}
			dn, err := findDistinguishedNameWithRetries(guid, lConn, adConfig)
			if errors.Is(err, LdapConnectionPermanentlyFailed{}) {
				logrus.Warnf("[%v] LDAP connection has permanently failed! will continue to migrate previously identified users", identifyAdUserOperation)
				skippedUsers = append(skippedUsers, skippedUserWorkUnit{guid: guid, originalUser: user.DeepCopy()})
				ldapPermanentlyFailed = true
			} else if errors.Is(err, LdapFoundDuplicateGuid{}) {
				logrus.Errorf("[%v] LDAP returned multiple users with GUID '%v'. this should not be possible, and may indicate a configuration error! this user will be skipped", identifyAdUserOperation, guid)
				skippedUsers = append(skippedUsers, skippedUserWorkUnit{guid: guid, originalUser: user.DeepCopy()})
			} else if errors.Is(err, LdapErrorNotFound{}) {
				logrus.Debugf("[%v] user %v is GUID-based (%v) and the Active Directory server doesn't know about it. marking it as missing", identifyAdUserOperation, user.Name, guid)
				knownGUIDMissingUnits[guid] = len(missingUsers)
				missingUsers = append(missingUsers, missingUserWorkUnit{guid: guid, originalUser: user.DeepCopy()})
			} else {
				logrus.Debugf("[%v] user %v is GUID-based (%v) and the Active Directory server knows it by the Distinguished Name '%v'", identifyAdUserOperation, user.Name, guid, dn)
				knownGUIDWorkUnits[guid] = len(usersToMigrate)
				knownDnWorkUnits[dn] = len(usersToMigrate)
				var emptyDuplicateList []*v3.User
				usersToMigrate = append(usersToMigrate, migrateUserWorkUnit{guid: guid, distinguishedName: dn, originalUser: user.DeepCopy(), duplicateUsers: emptyDuplicateList})
			}
		}
	}

	if len(usersToMigrate) == 0 {
		logrus.Debugf("[%v] found 0 users in need of migration, exiting without checking for DN-based duplicates", identifyAdUserOperation)
		return usersToMigrate, missingUsers, skippedUsers
	}

	// Now for the second pass, we need to identify DN-based users, and see if they are duplicates of any of the GUID
	// users that we found in the first pass. We'll prefer the oldest user as the originalUser object, this will be
	// the one we keep when we resolve duplicates later.
	logrus.Debugf("[%v] locating any DN-based Active Directory users", identifyAdUserOperation)
	for _, user := range users.Items {
		if !isAdUser(&user) {
			logrus.Debugf("[%v] user '%v' has no AD principals, skipping", identifyAdUserOperation, user.Name)
			continue
		}
		principalID := adPrincipalID(&user)
		logrus.Debugf("[%v] processing AD User '%v' with principal ID: '%v'", identifyAdUserOperation, user.Name, principalID)
		if isGUID(principalID) {
			logrus.Debugf("[%v] '%v' does not appear to be a DN-based principal ID, taking no action", identifyAdUserOperation, principalID)
			continue
		}
		dn, err := getExternalID(principalID)
		if err != nil {
			logrus.Errorf("[%v] failed to extract DN from principal '%v', cannot process user: '%v'", identifyAdUserOperation, err, user.Name)
			continue
		}
		if i, exists := knownDnWorkUnits[dn]; exists {
			logrus.Debugf("[%v] user %v is DN-based (%v), and a duplicate of %v",
				identifyAdUserOperation, user.Name, dn, usersToMigrate[i].originalUser.Name)
			// Make sure the oldest duplicate user is selected as the original
			if usersToMigrate[i].originalUser.CreationTimestamp.Time.After(user.CreationTimestamp.Time) {
				usersToMigrate[i].duplicateUsers = append(usersToMigrate[i].duplicateUsers, usersToMigrate[i].originalUser)
				usersToMigrate[i].originalUser = &user
			} else {
				usersToMigrate[i].duplicateUsers = append(usersToMigrate[i].duplicateUsers, &user)
			}
		}
	}

	return usersToMigrate, missingUsers, skippedUsers
}

func replaceGUIDPrincipalWithDn(user *v3.User, dn string, guid string, dryRun bool) {
	var principalIDs []string
	for _, principalID := range user.PrincipalIDs {
		if !strings.HasPrefix(principalID, activeDirectoryPrefix) {
			principalIDs = append(principalIDs, principalID)
		}
	}
	principalIDs = append(principalIDs, activeDirectoryPrefix+dn)
	user.PrincipalIDs = principalIDs

	// In dry run mode (and while debugging) we want to print the before/after state of the user principals
	if dryRun {
		logrus.Infof("[%v] User '%v' with GUID '%v' would have new principals:", migrateAdUserOperation,
			guid, user.Name)
		for _, principalID := range user.PrincipalIDs {
			logrus.Infof("[%v]     '%v'", migrateAdUserOperation, principalID)
		}
	} else {
		logrus.Debugf("[%v] User '%v' with GUID %v will have new principals:", migrateAdUserOperation,
			guid, user.Name)
		for _, principalID := range user.PrincipalIDs {
			logrus.Debugf("[%v]     '%v'", migrateAdUserOperation, principalID)
		}
	}
}

func isAdUser(user *v3.User) bool {
	for _, principalID := range user.PrincipalIDs {
		if strings.HasPrefix(principalID, activeDirectoryPrefix) {
			return true
		}
	}
	return false
}

func adPrincipalID(user *v3.User) string {
	for _, principalID := range user.PrincipalIDs {
		if strings.HasPrefix(principalID, activeDirectoryPrefix) {
			return principalID
		}
	}
	return ""
}

func localPrincipalID(user *v3.User) string {
	for _, principalID := range user.PrincipalIDs {
		if strings.HasPrefix(principalID, localPrefix) {
			return principalID
		}
	}
	return ""
}

func isDistinguishedName(principalID string) bool {
	// Note: this is the logic the original migration script used: DNs have commas
	// in them, and GUIDs do not. This seems... potentially fragile? Could a DN exist
	// in the root of the tree (or perhaps be specified relative to a branch?) and thus
	// be free of commas?
	return strings.Contains(principalID, ",")
}

func isGUID(principalID string) bool {
	return !isDistinguishedName(principalID)
}

func getExternalID(principalID string) (string, error) {
	parts := strings.Split(principalID, "://")
	if len(parts) != 2 {
		return "", fmt.Errorf("[%v] failed to parse invalid principalID: %v", identifyAdUserOperation, principalID)
	}
	return parts[1], nil
}

func migrateTokens(workunit *migrateUserWorkUnit, sc *config.ScaledContext, dryRun bool) error {
	tokenInterface := sc.Management.Tokens("")
	dnPrincipalID := activeDirectoryPrefix + workunit.distinguishedName
	for _, userToken := range workunit.guidTokens {
		if dryRun {
			logrus.Infof("[%v] DRY RUN: would migrate token '%v' from GUID principal '%v' to DN principal '%v'. "+
				"Additionally, it would add an annotation, %v, indicating the former principalID of this token "+
				"and a label, %v, to indicate that this token has been migrated",
				migrateTokensOperation, userToken.Name, userToken.UserPrincipal.Name, dnPrincipalID, adGUIDMigrationAnnotation, adGUIDMigrationLabel)
		} else {
			latestToken, err := tokenInterface.Get(userToken.Name, metav1.GetOptions{})
			if err != nil {
				logrus.Errorf("[%v] token %s no longer exists: %v", migrateTokensOperation, userToken.Name, err)
			}
			if latestToken.Annotations == nil {
				latestToken.Annotations = make(map[string]string)
			}
			latestToken.Annotations[adGUIDMigrationAnnotation] = workunit.guid
			if latestToken.Labels == nil {
				latestToken.Labels = make(map[string]string)
			}
			latestToken.Labels[tokens.UserIDLabel] = workunit.originalUser.Name
			latestToken.Labels[adGUIDMigrationLabel] = migratedLabelValue
			latestToken.UserPrincipal.Name = dnPrincipalID
			latestToken.UserID = workunit.originalUser.Name
			_, err = tokenInterface.Update(latestToken)
			if err != nil {
				return fmt.Errorf("[%v] unable to update token: %w", migrateTokensOperation, err)
			}
		}
	}

	localPrincipalID := localPrefix + workunit.originalUser.Name
	for _, userToken := range workunit.duplicateLocalTokens {
		if dryRun {
			logrus.Infof("[%v] DRY RUN: would migrate Token '%v' from duplicate local user '%v' to original user '%v'"+
				"Additionally, it would add an annotation, %v, indicating the former principalID of this token "+
				"and a label, %v, to indicate that this token has been migrated",
				migrateTokensOperation, userToken.Name, userToken.UserPrincipal.Name, localPrincipalID, adGUIDMigrationAnnotation, adGUIDMigrationLabel)
		} else {
			latestToken, err := tokenInterface.Get(userToken.Name, metav1.GetOptions{})
			if err != nil {
				logrus.Errorf("[%v] token %s no longer exists: %v", migrateTokensOperation, userToken.Name, err)
			}
			if latestToken.Annotations == nil {
				latestToken.Annotations = make(map[string]string)
			}
			latestToken.Annotations[adGUIDMigrationAnnotation] = workunit.guid
			if latestToken.Labels == nil {
				latestToken.Labels = make(map[string]string)
			}
			latestToken.Labels[tokens.UserIDLabel] = workunit.originalUser.Name
			latestToken.Labels[adGUIDMigrationLabel] = migratedLabelValue
			latestToken.UserPrincipal.Name = localPrincipalID
			latestToken.UserID = workunit.originalUser.Name
			_, err = tokenInterface.Update(latestToken)
			if err != nil {
				return fmt.Errorf("[%v] unable to update token: %w", migrateTokensOperation, err)
			}
		}
	}
	return nil
}

func collectTokens(workunits *[]migrateUserWorkUnit, sc *config.ScaledContext) error {
	tokenInterface := sc.Management.Tokens("")
	tokenList, err := tokenInterface.List(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("[%v] unable to fetch token objects: %v", migrateAdUserOperation, err)
		return err
	}

	for i, workunit := range *workunits {
		guidPrincipal := activeDirectoryPrefix + workunit.guid
		for _, token := range tokenList.Items {
			if guidPrincipal == token.UserPrincipal.Name || workunit.originalUser.Name == token.UserID {
				workunit.guidTokens = append(workunit.guidTokens, token)
			} else {
				for _, duplicateLocalUser := range workunit.duplicateUsers {
					if localPrincipalID(duplicateLocalUser) == token.UserPrincipal.Name {
						workunit.duplicateLocalTokens = append(workunit.duplicateLocalTokens, token)
					}
				}
			}
		}
		(*workunits)[i] = workunit
	}

	return nil
}

func workUnitContainsName(workunit *migrateUserWorkUnit, name string) bool {
	if workunit.originalUser.Name == name {
		return true
	}
	for _, duplicateLocalUser := range workunit.duplicateUsers {
		if duplicateLocalUser.Name == name {
			return true
		}
	}
	return false
}

func collectCRTBs(workunits *[]migrateUserWorkUnit, sc *config.ScaledContext) error {
	crtbInterface := sc.Management.ClusterRoleTemplateBindings("")
	crtbList, err := crtbInterface.List(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("[%v] unable to fetch CRTB objects: %v", migrateAdUserOperation, err)
		return err
	}

	// first build a map of guid-principalid -> work unit, which will make the following logic more efficient
	originalGUIDWorkUnits := map[string]int{}
	duplicateGUIDWorkUnits := map[string]int{}
	for i, workunit := range *workunits {
		originalGUIDWorkUnits[activeDirectoryPrefix+workunit.guid] = i
		for j := range workunit.duplicateUsers {
			duplicateGUIDWorkUnits[activeDirectoryPrefix+workunit.guid] = j
		}
	}

	for _, crtb := range crtbList.Items {
		if index, exists := originalGUIDWorkUnits[crtb.UserPrincipalName]; exists {
			if workUnitContainsName(&(*workunits)[index], crtb.UserName) {
				(*workunits)[index].guidCRTBs = append((*workunits)[index].guidCRTBs, crtb)
			}
		} else if index, exists = duplicateGUIDWorkUnits[crtb.UserPrincipalName]; exists {
			if workUnitContainsName(&(*workunits)[index], crtb.UserName) {
				(*workunits)[index].duplicateLocalCRTBs = append((*workunits)[index].duplicateLocalCRTBs, crtb)
			}
		}
	}

	return nil
}

func collectPRTBs(workunits *[]migrateUserWorkUnit, sc *config.ScaledContext) error {
	prtbInterface := sc.Management.ProjectRoleTemplateBindings("")
	prtbList, err := prtbInterface.List(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("[%v] unable to fetch PRTB objects: %v", migrateAdUserOperation, err)
		return err
	}

	// first build a map of guid-principalid -> work unit, which will make the following logic more efficient
	originalGUIDWorkUnits := map[string]int{}
	duplicateGUIDWorkUnits := map[string]int{}
	for i, workunit := range *workunits {
		originalGUIDWorkUnits[activeDirectoryPrefix+workunit.guid] = i
		for j := range workunit.duplicateUsers {
			duplicateGUIDWorkUnits[activeDirectoryPrefix+workunit.guid] = j
		}
	}

	for _, prtb := range prtbList.Items {
		if index, exists := originalGUIDWorkUnits[prtb.UserPrincipalName]; exists {
			if workUnitContainsName(&(*workunits)[index], prtb.UserName) {
				(*workunits)[index].guidPRTBs = append((*workunits)[index].guidPRTBs, prtb)
			}
		} else if index, exists = duplicateGUIDWorkUnits[prtb.UserPrincipalName]; exists {
			if workUnitContainsName(&(*workunits)[index], prtb.UserName) {
				(*workunits)[index].duplicateLocalPRTBs = append((*workunits)[index].duplicateLocalPRTBs, prtb)
			}
		}
	}

	return nil
}

func migrateCRTBs(workunit *migrateUserWorkUnit, sc *config.ScaledContext, dryRun bool) error {
	crtbInterface := sc.Management.ClusterRoleTemplateBindings("")
	// First convert all GUID-based CRTBs to their equivalent Distinguished Name variants
	dnPrincipalID := activeDirectoryPrefix + workunit.distinguishedName
	for _, oldCrtb := range workunit.guidCRTBs {
		if dryRun {
			logrus.Infof("[%v] DRY RUN: would migrate CRTB '%v' from GUID principal '%v' to DN principal '%v'. "+
				"Additionally, an annotation, %v, would be added containing the principal being migrated from and"+
				"labels, %v and %v, that will contain the name of the previous CRTB and indicate that this CRTB has been migrated.",
				migrateCrtbsOperation, oldCrtb.Name, oldCrtb.UserPrincipalName, dnPrincipalID, adGUIDMigrationAnnotation, migrationPreviousName, adGUIDMigrationLabel)
		} else {
			newAnnotations := oldCrtb.Annotations
			if newAnnotations == nil {
				newAnnotations = make(map[string]string)
			}
			newAnnotations[adGUIDMigrationAnnotation] = oldCrtb.UserPrincipalName
			newLabels := oldCrtb.Labels
			if newLabels == nil {
				newLabels = make(map[string]string)
			}
			newLabels[migrationPreviousName] = oldCrtb.Name
			newLabels[adGUIDMigrationLabel] = migratedLabelValue
			newCrtb := &v3.ClusterRoleTemplateBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:         "",
					Namespace:    oldCrtb.ObjectMeta.Namespace,
					GenerateName: "crtb-",
					Annotations:  newAnnotations,
					Labels:       newLabels,
				},
				ClusterName:       oldCrtb.ClusterName,
				UserName:          workunit.originalUser.Name,
				RoleTemplateName:  oldCrtb.RoleTemplateName,
				UserPrincipalName: dnPrincipalID,
			}
			_, err := crtbInterface.Create(newCrtb)
			if err != nil {
				return fmt.Errorf("[%v] unable to create new CRTB: %w", migrateCrtbsOperation, err)
			}
			err = sc.Management.ClusterRoleTemplateBindings("").DeleteNamespaced(oldCrtb.Namespace, oldCrtb.Name, &metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("[%v] unable to delete CRTB: %w", migrateCrtbsOperation, err)
			}
		}
	}
	// Now do the same for Local ID bindings on the users we are about to delete, pointing them instead to the merged
	// original user that we will be keeping
	localPrincipalID := localPrefix + workunit.originalUser.Name
	for _, oldCrtb := range workunit.duplicateLocalCRTBs {
		if dryRun {
			logrus.Infof("[%v] DRY RUN: would migrate CRTB '%v' from duplicate local user '%v' to original user '%v'"+
				"Additionally, an annotation, %v, would be added containing the principal being migrated from and"+
				"labels, %v and %v, that will contain the name of the previous CRTB and indicate that this CRTB has been migrated.",
				migrateCrtbsOperation, oldCrtb.Name, oldCrtb.UserPrincipalName, localPrincipalID, adGUIDMigrationAnnotation, migrationPreviousName, adGUIDMigrationLabel)
		} else {
			newAnnotations := oldCrtb.Annotations
			if newAnnotations == nil {
				newAnnotations = make(map[string]string)
			}
			newAnnotations[adGUIDMigrationAnnotation] = oldCrtb.UserPrincipalName
			newLabels := oldCrtb.Labels
			if newLabels == nil {
				newLabels = make(map[string]string)
			}
			newLabels[migrationPreviousName] = oldCrtb.Name
			newLabels[adGUIDMigrationLabel] = migratedLabelValue
			newCrtb := &v3.ClusterRoleTemplateBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:         "",
					Namespace:    oldCrtb.ObjectMeta.Namespace,
					GenerateName: "crtb-",
					Annotations:  newAnnotations,
					Labels:       newLabels,
				},
				ClusterName:       oldCrtb.ClusterName,
				UserName:          workunit.originalUser.Name,
				RoleTemplateName:  oldCrtb.RoleTemplateName,
				UserPrincipalName: localPrincipalID,
			}
			_, err := crtbInterface.Create(newCrtb)
			if err != nil {
				return fmt.Errorf("[%v] unable to create new CRTB: %w", migrateCrtbsOperation, err)
			}
			err = sc.Management.ClusterRoleTemplateBindings("").DeleteNamespaced(oldCrtb.Namespace, oldCrtb.Name, &metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("[%v] unable to delete CRTB: %w", migrateCrtbsOperation, err)
			}
		}
	}
	return nil
}

func migratePRTBs(workunit *migrateUserWorkUnit, sc *config.ScaledContext, dryRun bool) error {
	prtbInterface := sc.Management.ProjectRoleTemplateBindings("")
	// First convert all GUID-based PRTBs to their equivalent Distinguished Name variants
	dnPrincipalID := activeDirectoryPrefix + workunit.distinguishedName
	for _, oldPrtb := range workunit.guidPRTBs {
		if dryRun {
			logrus.Infof("[%v] DRY RUN: would migrate PRTB '%v' from GUID principal '%v' to DN principal '%v'. "+
				"Additionally, an annotation, %v, would be added containing the principal being migrated from and"+
				"labels, %v and %v, that will contain the name of the previous PRTB and indicate that this PRTB has been migrated.",
				migrateCrtbsOperation, oldPrtb.Name, oldPrtb.UserPrincipalName, dnPrincipalID, adGUIDMigrationAnnotation, migrationPreviousName, adGUIDMigrationLabel)

		} else {
			newAnnotations := oldPrtb.Annotations
			if newAnnotations == nil {
				newAnnotations = make(map[string]string)
			}
			newAnnotations[adGUIDMigrationAnnotation] = oldPrtb.UserPrincipalName
			newLabels := oldPrtb.Labels
			if newLabels == nil {
				newLabels = make(map[string]string)
			}
			newLabels[migrationPreviousName] = oldPrtb.Name
			newLabels[adGUIDMigrationLabel] = migratedLabelValue
			newPrtb := &v3.ProjectRoleTemplateBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:         "",
					Namespace:    oldPrtb.ObjectMeta.Namespace,
					GenerateName: "prtb-",
					Annotations:  newAnnotations,
					Labels:       newLabels,
				},
				ProjectName:       oldPrtb.ProjectName,
				UserName:          workunit.originalUser.Name,
				RoleTemplateName:  oldPrtb.RoleTemplateName,
				UserPrincipalName: dnPrincipalID,
			}
			_, err := prtbInterface.Create(newPrtb)
			if err != nil {
				return fmt.Errorf("[%v] unable to create new PRTB: %w", migratePrtbsOperation, err)
			}
			err = sc.Management.ProjectRoleTemplateBindings("").DeleteNamespaced(oldPrtb.Namespace, oldPrtb.Name, &metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("[%v] unable to delete PRTB: %w", migratePrtbsOperation, err)
			}
		}
	}
	// Now do the same for Local ID bindings on the users we are about to delete, pointing them instead to the merged
	// original user that we will be keeping
	localPrincipalID := localPrefix + workunit.originalUser.Name
	for _, oldPrtb := range workunit.duplicateLocalPRTBs {
		if dryRun {
			logrus.Infof("[%v] DRY RUN: would migrate PRTB '%v' from duplicate local user '%v' to original user '%v'"+
				"Additionally, an annotation, %v, would be added containing the principal being migrated from and"+
				"labels, %v and %v, that will contain the name of the previous PRTB and indicate that this PRTB has been migrated.",
				migrateCrtbsOperation, oldPrtb.Name, oldPrtb.UserPrincipalName, localPrincipalID, adGUIDMigrationAnnotation, migrationPreviousName, adGUIDMigrationLabel)

		} else {
			newAnnotations := oldPrtb.Annotations
			if newAnnotations == nil {
				newAnnotations = make(map[string]string)
			}
			newAnnotations[adGUIDMigrationAnnotation] = oldPrtb.UserPrincipalName
			newLabels := oldPrtb.Labels
			if newLabels == nil {
				newLabels = make(map[string]string)
			}
			newLabels[migrationPreviousName] = oldPrtb.Name
			newLabels[adGUIDMigrationLabel] = migratedLabelValue
			newPrtb := &v3.ProjectRoleTemplateBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:         "",
					Namespace:    oldPrtb.ObjectMeta.Namespace,
					GenerateName: "prtb-",
					Annotations:  newAnnotations,
					Labels:       newLabels,
				},
				ProjectName:       oldPrtb.ProjectName,
				UserName:          workunit.originalUser.Name,
				RoleTemplateName:  oldPrtb.RoleTemplateName,
				UserPrincipalName: localPrincipalID,
			}
			_, err := prtbInterface.Create(newPrtb)
			if err != nil {
				return fmt.Errorf("[%v] unable to create new PRTB: %w", migratePrtbsOperation, err)
			}
			err = sc.Management.ProjectRoleTemplateBindings("").DeleteNamespaced(oldPrtb.Namespace, oldPrtb.Name, &metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("[%v] unable to delete PRTB: %w", migratePrtbsOperation, err)
			}
		}
	}
	return nil
}

func updateMigrationStatus(sc *config.ScaledContext, status string, value string) error {
	cm, err := sc.Core.ConfigMaps(activedirectory.StatusConfigMapNamespace).Get(activedirectory.StatusConfigMapName, metav1.GetOptions{})
	if err != nil {
		// Create a new ConfigMap if it doesn't exist
		if !apierrors.IsNotFound(err) {
			return err
		}
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      activedirectory.StatusConfigMapName,
				Namespace: activedirectory.StatusConfigMapNamespace,
			},
		}
	}

	cm.Data = map[string]string{status: value}

	if _, err := sc.Core.ConfigMaps(activedirectory.StatusConfigMapNamespace).Update(cm); err != nil {
		// If the ConfigMap does not exist, create it
		if apierrors.IsNotFound(err) {
			_, err = sc.Core.ConfigMaps(activedirectory.StatusConfigMapNamespace).Create(cm)
			if err != nil {
				return fmt.Errorf("[%v] unable to create migration status configmap: %v", migrateAdUserOperation, err)
			}
		}
	}

	return nil
}
