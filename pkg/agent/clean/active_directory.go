//go:build !windows
// +build !windows

/*
Look for any active directory users with a GUID type principal.
Convert these users to a distinguished name instead.
*/

package clean

import (
	"bytes"
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
	"github.com/rancher/norman/store/proxy"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/providers/common/ldap"
	v3client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/rancher/wrangler/pkg/ratelimit"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	listAdUsersOperation     = "list-ad-users"
	migrateAdUserOperation   = "migrate-ad-user"
	activeDirectoryPrefix    = "activedirectory_user://"
	statusConfigMapName      = "ad-guid-migration"
	statusConfigMapNamespace = "cattle-system"
)

type migrateUserWorkUnit struct {
	distinguishedName string
	guid              string
	originalUser      *v3.User
	duplicateUsers    []*v3.User
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

	sc.UserManager, err = common.NewUserManagerNoBindings(sc)
	if err != nil {
		logrus.Errorf("[%v] failed to create sc.UserManager: %v", migrateAdUserOperation, err)
		return nil, err
	}

	sc.ClientGetter, err = proxy.NewClientGetterFromConfig(*restConfig)
	if err != nil {
		logrus.Errorf("[%v] failed to create sc.ClientGetter: %v", migrateAdUserOperation, err)
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

	logrus.Infof("[%v] Should in theory have ActiveDirectory config data? Let's check!", listAdUsersOperation)
	logrus.Infof("[%v] AD Service Account User: %v", listAdUsersOperation, storedADConfig.ServiceAccountUsername)

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
func EscapeUUID(s string) string {
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
	query := fmt.Sprintf("(%v=%v)", "objectGUID", EscapeUUID(guid))
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
		return "", LdapErrorNotFound{}
	}

	entry := result.Entries[0]

	return entry.DN, nil
}

func findDistinguishedNameWithRetries(guid string, lConn *ldapv3.Conn, adConfig *v3.ActiveDirectoryConfig) (string, error) {
	const maxRetries = 5
	const retryDelay = time.Duration(10 * time.Second)

	for retry := 0; retry < maxRetries; retry++ {
		distinguishedName, err := findDistinguishedName(guid, lConn, adConfig)
		if err == nil || errors.Is(err, LdapErrorNotFound{}) {
			return distinguishedName, err
		}
		logrus.Warnf("[%v] LDAP connection failed: '%v', retrying in %v...", listAdUsersOperation, err, retryDelay.Seconds())
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
			logrus.Errorf("[%v] error in building the cluster config %v", listAdUsersOperation, err)
			return nil, nil, err
		}
	}
	restConfig.RateLimiter = ratelimit.None

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

// ListAdUsers is purely for debugging. If this is still here, fail the PR. :P
func ListAdUsers(clientConfig *restclient.Config) error {
	if os.Getenv("DRY_RUN") == "true" {
		logrus.Infof("[%v] DRY_RUN is true, no objects will be deleted/modified", listAdUsersOperation)
		dryRun = true
	}

	sc, adConfig, err := prepareClientContexts(clientConfig)
	if err != nil {
		return err
	}

	// We'll share this lConn for all lookups to hopefully speed things along
	lConn, err := ldapConnection(adConfig)
	if err != nil {
		return err
	}
	defer lConn.Close()

	err = updateMigrationStatus(sc, "ad-guid-migration-status", "Running")
	if err != nil {
		return fmt.Errorf("unable to update migration status configmap: %v", err)
	}

	users, err := sc.Management.Users("").List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to fetch user list: %v", err)
	}

	usersToMigrate, missingUsers, skippedUsers := identifyMigrationWorkUnits(users, lConn, adConfig)

	for _, user := range skippedUsers {
		logrus.Errorf("[%v] Unable to migrate user %v due to a connection failure. This user will be skipped!", listAdUsersOperation, user.originalUser.Name)
	}
	for _, user := range missingUsers {
		logrus.Errorf("[%v] User %v with GUID %v does not seem to exist in Active Directory. They may have been deleted. This user will be skipped!", listAdUsersOperation, user.originalUser.Name, user.guid)
	}

	for _, userToMigrate := range usersToMigrate {
		dnPrincipal := activeDirectoryPrefix + userToMigrate.distinguishedName
		// If any of the binding replacements fail, then the resulting rancher state for this user is inconsistent
		//   and we should NOT attempt to modify the user or delete any of its duplicates. This situation is unusual
		//   and must be investigated by the local admin.
		err := migrateTokens(userToMigrate.originalUser.Name, dnPrincipal, sc, dryRun)
		if err != nil {
			logrus.Errorf("[%v] unable to migrate tokens for user %v: %v", listAdUsersOperation, userToMigrate.originalUser.Name, err)
			continue
		}
		err = migrateCRTB(userToMigrate.guid, dnPrincipal, sc, dryRun)
		if err != nil {
			logrus.Errorf("[%v] unable to migrate CRTBs for user %v: %v", listAdUsersOperation, userToMigrate.originalUser.Name, err)
			continue
		}
		err = migratePRTB(userToMigrate.guid, dnPrincipal, sc, dryRun)
		if err != nil {
			logrus.Errorf("[%v] unable to migrate PRTBs for user %v: %v", listAdUsersOperation, userToMigrate.originalUser.Name, err)
			continue
		}
		replaceGuidPrincipalWithDn(userToMigrate.originalUser, userToMigrate.distinguishedName)

		// In dry run mode (and while debugging) we want to print the before/after state of the user principals
		if dryRun {
			logrus.Infof("[%v] User '%v' with GUID %v would have new principals:", listAdUsersOperation,
				userToMigrate.guid, userToMigrate.originalUser.Name)
			for _, principalId := range userToMigrate.originalUser.PrincipalIDs {
				logrus.Infof("[%v]     '%v'", listAdUsersOperation, principalId)
			}
		} else {
			logrus.Debugf("[%v] User '%v' with GUID %v will have new principals:", listAdUsersOperation,
				userToMigrate.guid, userToMigrate.originalUser.Name)
			for _, principalId := range userToMigrate.originalUser.PrincipalIDs {
				logrus.Debugf("[%v]     '%v'", listAdUsersOperation, principalId)
			}
		}

		// ... okay, moment of truth then. Let's save and see what happens!
		if dryRun {
			logrus.Infof("DRY RUN: changes to user %v have NOT been saved.", userToMigrate.originalUser.Name)
			if len(userToMigrate.duplicateUsers) > 0 {
				logrus.Infof("[%v] DRY RUN: duplicate users were identified! These users would be deleted:", listAdUsersOperation)
				for _, duplicateUser := range userToMigrate.duplicateUsers {
					logrus.Infof("[%v] DRY RUN: would DELETE user %v", listAdUsersOperation, duplicateUser.Name)
				}
			}
		} else {
			// First delete all the duplicate users
			for _, duplicateUser := range userToMigrate.duplicateUsers {
				err = sc.Management.Users("").Delete(duplicateUser.Name, &metav1.DeleteOptions{})
				if err != nil {
					logrus.Errorf("[%v] failed to delete dupliate user '%v' with: %v", listAdUsersOperation, userToMigrate.originalUser.Name, err)
					// If the duplicate deletion has failed for some reason, it is NOT safe to save the modified user, as
					// this may result in a duplicate AD principal ID. Notify and skip.
					logrus.Errorf("[%v] cannot safely save modifications to user %v, skipping", listAdUsersOperation, userToMigrate.originalUser.Name)
					continue
				} else {
					logrus.Infof("[%v] deleted duplicate user %v", listAdUsersOperation, duplicateUser.Name)
				}
			}
			// Having updated all permissions bindings and resolved all potential principal ID conflicts, it is
			// finally safe to save the modified original user
			_, err = sc.Management.Users("").Update(userToMigrate.originalUser)
			if err != nil {
				logrus.Errorf("[%v] failed to save modified user '%v' with: %v", listAdUsersOperation, userToMigrate.originalUser.Name, err)
			}
			logrus.Infof("[%v] user %v was successfully migrated", listAdUsersOperation, userToMigrate.originalUser.Name)
		}
	}

	err = updateMigrationStatus(sc, "ad-guid-migration-status", "Finished")
	if err != nil {
		return fmt.Errorf("unable to update migration status configmap: %v", err)
	}

	return nil
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
	knownGuidWorkUnits := map[string]int{}
	knownGuidMissingUnits := map[string]int{}
	knownDnWorkUnits := map[string]int{}

	// Now we'll make two passes over the list of all users. First we need to identify any GUID based users, and
	// sort them into "found" and "not found" lists. At this stage we might have GUID-based duplicates, and we'll
	// detect and sort those accordingly
	ldapPermanentlyFailed := false
	logrus.Debugf("[%v] Locating any GUID-based Active Directory users...", listAdUsersOperation)
	for _, user := range users.Items {
		if !isAdUser(&user) {
			logrus.Debugf("[%v] User '%v' has no AD principals, skipping", listAdUsersOperation, user.Name)
			continue
		}
		principalId := adPrincipalId(&user)
		logrus.Debugf("[%v] Processing AD User '%v' with principal ID: '%v'", listAdUsersOperation, user.Name, principalId)
		if !isGuid(principalId) {
			logrus.Debugf("[%v] '%v' Does not appear to be a GUID-based principal ID, taking no action.", listAdUsersOperation, principalId)
			continue
		}
		guid, _, err := getExternalIdAndScope(principalId)
		if err != nil {
			// This really shouldn't be possible to hit, since isGuid will fail to parse anything that would
			// cause getExternalIdAndScope to choke on the input, but for maximum safety we'll handle it anyway.
			logrus.Errorf("[%v] Failed to extract GUID from principal '%v', cannot process this user! (%v)", listAdUsersOperation, err, user.Name)
			continue
		}
		// If our LDAP connection has gone sour, we still need to log this user for reporting
		if ldapPermanentlyFailed {
			skippedUsers = append(skippedUsers, skippedUserWorkUnit{guid: guid, originalUser: user.DeepCopy()})
		} else {
			// Check for guid-based duplicates here. If we find one, we don't need to perform an other LDAP lookup.
			if i, exists := knownGuidWorkUnits[guid]; exists {
				logrus.Debugf("[%v] User %v is GUID-based (%v) and a duplicate of %v",
					listAdUsersOperation, user.Name, guid, usersToMigrate[i].originalUser.Name)
				// Make sure the oldest duplicate user is selected as the original
				if usersToMigrate[i].originalUser.CreationTimestamp.Time.After(user.CreationTimestamp.Time) {
					usersToMigrate[i].duplicateUsers = append(usersToMigrate[i].duplicateUsers, usersToMigrate[i].originalUser)
					usersToMigrate[i].originalUser = user.DeepCopy()
				} else {
					usersToMigrate[i].duplicateUsers = append(usersToMigrate[i].duplicateUsers, user.DeepCopy())
				}
				continue
			}
			if i, exists := knownGuidMissingUnits[guid]; exists {
				logrus.Debugf("[%v] User %v is GUID-based (%v) and a duplicate of %v which is known to be missing",
					listAdUsersOperation, user.Name, guid, missingUsers[i].originalUser.Name)
				// We're less picky about the age of the oldest user here, because we aren't going to deduplicate these
				missingUsers[i].duplicateUsers = append(missingUsers[i].duplicateUsers, user.DeepCopy())
				continue
			}
			dn, err := findDistinguishedNameWithRetries(guid, lConn, adConfig)
			if errors.Is(err, LdapConnectionPermanentlyFailed{}) {
				logrus.Warnf("[%v] LDAP connection has permanently failed! Will proceed to migrate the users we were able to identify up to this point.", listAdUsersOperation)
				skippedUsers = append(skippedUsers, skippedUserWorkUnit{guid: guid, originalUser: user.DeepCopy()})
				ldapPermanentlyFailed = true
			} else if errors.Is(err, LdapErrorNotFound{}) {
				logrus.Debugf("[%v] User %v is GUID-based (%v) and the Active Directory server doesn't know about it. Marking it as missing!", listAdUsersOperation, user.Name, guid)
				knownGuidMissingUnits[guid] = len(missingUsers)
				missingUsers = append(missingUsers, missingUserWorkUnit{guid: guid, originalUser: user.DeepCopy()})
			} else {
				logrus.Debugf("[%v] User %v is GUID-based (%v) and the Active Directory server knows it by the Distinguished Name '%v'", listAdUsersOperation, user.Name, guid, dn)
				knownGuidWorkUnits[guid] = len(usersToMigrate)
				knownDnWorkUnits[dn] = len(usersToMigrate)
				var emptyDuplicateList []*v3.User
				usersToMigrate = append(usersToMigrate, migrateUserWorkUnit{guid: guid, distinguishedName: dn, originalUser: user.DeepCopy(), duplicateUsers: emptyDuplicateList})
			}
		}
	}

	if len(usersToMigrate) == 0 {
		logrus.Debugf("[%v] Found 0 users in need of migration, exiting without checking for DN-based duplicates.", listAdUsersOperation)
		return usersToMigrate, missingUsers, skippedUsers
	}

	// Now for the second pass, we need to identify DN-based users, and see if they are duplicates of any of the GUID
	// users that we found in the first pass. We'll prefer the oldest user as the originalUser object, this will be
	// the one we keep when we resolve duplicates later.
	logrus.Debugf("[%v] Locating any DN-based Active Directory users...", listAdUsersOperation)
	for _, user := range users.Items {
		if !isAdUser(&user) {
			logrus.Debugf("[%v] User '%v' has no AD principals, skipping", listAdUsersOperation, user.Name)
			continue
		}
		principalId := adPrincipalId(&user)
		logrus.Debugf("[%v] Processing AD User '%v' with principal ID: '%v'", listAdUsersOperation, user.Name, principalId)
		if isGuid(principalId) {
			logrus.Debugf("[%v] '%v' Does not appear to be a DN-based principal ID, taking no action.", listAdUsersOperation, principalId)
			continue
		}
		dn, _, err := getExternalIdAndScope(principalId)
		if err != nil {
			logrus.Errorf("[%v] Failed to extract DN from principal '%v', cannot process this user! (%v)", listAdUsersOperation, err, user.Name)
			continue
		}
		if i, exists := knownDnWorkUnits[dn]; exists {
			logrus.Debugf("[%v] User %v is DN-based (%v), and a duplicate of %v",
				listAdUsersOperation, user.Name, dn, usersToMigrate[i].originalUser.Name)
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

func replaceGuidPrincipalWithDn(user *v3.User, dn string) {
	var principalIDs []string
	for _, principalId := range user.PrincipalIDs {
		if !strings.HasPrefix(principalId, activeDirectoryPrefix) {
			principalIDs = append(principalIDs, principalId)
		}
	}
	principalIDs = append(principalIDs, activeDirectoryPrefix+dn)
	user.PrincipalIDs = principalIDs
}

func isAdUser(user *v3.User) bool {
	for _, principalId := range user.PrincipalIDs {
		if strings.HasPrefix(principalId, activeDirectoryPrefix) {
			return true
		}
	}
	return false
}

func adPrincipalId(user *v3.User) string {
	for _, principalId := range user.PrincipalIDs {
		if strings.HasPrefix(principalId, activeDirectoryPrefix) {
			return principalId
		}
	}
	return ""
}

func isDistinguishedName(principalId string) bool {
	// Note: this is the logic the original migration script used: DNs have commas
	// in them, and GUIDs do not. This seems... potentially fragile? Could a DN exist
	// in the root of the tree (or perhaps be specified relative to a branch?) and thus
	// be free of commas?
	return strings.Contains(principalId, ",")
}

func isGuid(principalId string) bool {
	return !isDistinguishedName(principalId)
}

func getExternalIdAndScope(principalID string) (string, string, error) {
	parts := strings.SplitN(principalID, ":", 2)
	if len(parts) != 2 {
		return "", "", errors.Errorf("invalid id %v", principalID)
	}
	scope := parts[0]
	externalID := strings.TrimPrefix(parts[1], "//")
	return externalID, scope, nil
}

func migrateTokens(userName string, newPrincipalID string, sc *config.ScaledContext, dryRun bool) error {
	tokenLabelSelector := labels.SelectorFromSet(labels.Set{
		"authn.management.cattle.io/token-userId": userName,
	})
	tokenListOptions := metav1.ListOptions{
		LabelSelector: tokenLabelSelector.String(),
	}
	tokenInterface := sc.Management.Tokens("")

	tokens, err := tokenInterface.List(tokenListOptions)
	if err != nil {
		return fmt.Errorf("failed to fetch tokens: %w", err)
	}

	for _, userToken := range tokens.Items {
		userToken.UserPrincipal.Name = newPrincipalID
		if dryRun {
			logrus.Infof("Dry Run:  Skipping update of %s", userToken.Name)
		} else {
			_, err := tokenInterface.Update(&userToken)
			if err != nil {
				logrus.Errorf("unable to update token %v for principalId %v: %v", userToken.Name, newPrincipalID, err)
			}
		}
	}
	return nil
}

func migrateCRTB(guid string, newPrincipalID string, sc *config.ScaledContext, dryRun bool) error {
	crtbInterface := sc.Management.ClusterRoleTemplateBindings("")
	crtbList, err := crtbInterface.List(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("unable to fetch CRTB objects")
	}

	for _, oldCrtb := range crtbList.Items {
		if activeDirectoryPrefix+guid == oldCrtb.UserPrincipalName {
			if dryRun {
				logrus.Infof("Dry Run:  Skipping update of %s", oldCrtb.Name)
			} else {
				newCrtb := &v3.ClusterRoleTemplateBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:         "",
						Namespace:    oldCrtb.ObjectMeta.Namespace,
						GenerateName: "crtb-",
					},
					ClusterName:       oldCrtb.ClusterName,
					UserName:          oldCrtb.UserName,
					RoleTemplateName:  oldCrtb.RoleTemplateName,
					UserPrincipalName: newPrincipalID,
				}
				_, err := crtbInterface.Create(newCrtb)
				if err != nil {
					return fmt.Errorf("unable to create new CRTB: %w", err)
				}
				err = sc.Management.ClusterRoleTemplateBindings("").DeleteNamespaced(oldCrtb.Namespace, oldCrtb.Name, &metav1.DeleteOptions{})
				if err != nil {
					return fmt.Errorf("unable to delete CRTB: %w", err)
				}
			}
		}
	}
	return nil
}

func migratePRTB(guid string, newPrincipalID string, sc *config.ScaledContext, dryRun bool) error {
	prtbInterface := sc.Management.ProjectRoleTemplateBindings("")
	prtbList, err := prtbInterface.List(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("unable to fetch PRTB objects")
	}

	for _, oldPrtb := range prtbList.Items {
		if activeDirectoryPrefix+guid == oldPrtb.UserPrincipalName {
			if dryRun {
				logrus.Infof("Dry Run:  Skipping update of %s", oldPrtb.Name)
			} else {
				newPrtb := &v3.ProjectRoleTemplateBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name:         "",
						Namespace:    oldPrtb.ObjectMeta.Namespace,
						GenerateName: "prtb-",
					},
					ProjectName:       oldPrtb.ProjectName,
					UserName:          oldPrtb.UserName,
					RoleTemplateName:  oldPrtb.RoleTemplateName,
					UserPrincipalName: newPrincipalID,
				}
				_, err := prtbInterface.Create(newPrtb)
				if err != nil {
					return fmt.Errorf("unable to create new PRTB: %w", err)
				}
				err = sc.Management.ProjectRoleTemplateBindings("").DeleteNamespaced(oldPrtb.Namespace, oldPrtb.Name, &metav1.DeleteOptions{})
				if err != nil {
					return fmt.Errorf("unable to delete PRTB: %w", err)
				}
			}
		}
	}
	return nil
}

func updateMigrationStatus(sc *config.ScaledContext, status string, value string) error {
	cm, err := sc.Core.ConfigMaps(statusConfigMapNamespace).Get(statusConfigMapName, metav1.GetOptions{})
	if err != nil {
		// Create a new ConfigMap if it doesn't exist
		if !apierrors.IsNotFound(err) {
			return err
		}
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{
				Name:      statusConfigMapName,
				Namespace: statusConfigMapNamespace,
			},
		}
	}

	cm.Data = map[string]string{status: value}

	if _, err := sc.Core.ConfigMaps(statusConfigMapNamespace).Update(cm); err != nil {
		// If the ConfigMap does not exist, create it
		if apierrors.IsNotFound(err) {
			_, err = sc.Core.ConfigMaps(statusConfigMapNamespace).Create(cm)
			if err != nil {
				return fmt.Errorf("unable to create migration status configmap: %v", err)
			}
		}
	}

	return nil
}
