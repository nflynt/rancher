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
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"os"
	"strings"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
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
	logrus.Infof("[%v] AD Service Account Pass: %v", listAdUsersOperation, storedADConfig.ServiceAccountPassword)

	if storedADConfig.ServiceAccountPassword != "" {
		value, err := common.ReadFromSecret(secrets, storedADConfig.ServiceAccountPassword,
			strings.ToLower(v3client.ActiveDirectoryConfigFieldServiceAccountPassword))
		if err != nil {
			return nil, err
		}
		storedADConfig.ServiceAccountPassword = value
	}

	logrus.Infof("[%v] AD Service Account Pass from Secret: %v", listAdUsersOperation, storedADConfig.ServiceAccountPassword)

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

func ldapConnection(config *v3.ActiveDirectoryConfig, caPool *x509.CertPool) (*ldapv3.Conn, error) {
	servers := config.Servers
	TLS := config.TLS
	port := config.Port
	connectionTimeout := config.ConnectionTimeout
	startTLS := config.StartTLS
	return ldap.NewLDAPConn(servers, TLS, startTLS, port, connectionTimeout, caPool)
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

func findDistinguishedName(guid string, adConfig *v3.ActiveDirectoryConfig) (string, error) {
	caPool, err := newCAPool(adConfig.Certificate)
	if err != nil {
		return "", fmt.Errorf("unable to create caPool: %v", err)
	}

	lConn, err := ldapConnection(adConfig, caPool)
	if err != nil {
		return "", err
	}
	defer lConn.Close()

	serviceAccountUsername := ldap.GetUserExternalID(adConfig.ServiceAccountUsername, adConfig.DefaultLoginDomain)
	err = lConn.Bind(serviceAccountUsername, adConfig.ServiceAccountPassword)
	if err != nil {
		return "", err
	}

	query := fmt.Sprintf("(%v=%v)", "objectGUID", EscapeUUID(guid))
	search := ldapv3.NewSearchRequest(adConfig.UserSearchBase, ldapv3.ScopeWholeSubtree, ldapv3.NeverDerefAliases,
		0, 0, false,
		query, ldap.GetUserSearchAttributes("memberOf", "objectClass", adConfig), nil)

	result, err := lConn.Search(search)
	if err != nil {
		return "", err
	}

	if len(result.Entries) < 1 {
		return "", httperror.NewAPIError(httperror.NotFound, fmt.Sprintf("%v not found", query))
	} else if len(result.Entries) > 1 {
		return "", fmt.Errorf("ldap user search found more than one result")
	}

	entry := result.Entries[0]

	return entry.DN, nil
}

// ListAdUsers is purely for debugging. If this is still here, fail the PR. :P
func ListAdUsers(clientConfig *restclient.Config) error {
	if os.Getenv("DRY_RUN") == "true" {
		logrus.Infof("[%v] DRY_RUN is true, no objects will be deleted/modified", listAdUsersOperation)
		dryRun = true
	}

	var restConfig *restclient.Config
	var err error
	if clientConfig != nil {
		restConfig = clientConfig
	} else {
		restConfig, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			logrus.Errorf("[%v] error in building the cluster config %v", listAdUsersOperation, err)
			return err
		}
	}
	restConfig.RateLimiter = ratelimit.None

	sc, err := scaledContext(restConfig)
	if err != nil {
		return err
	}
	adConfig, err := adConfiguration(sc)
	if err != nil {
		return err
	}

	err = updateMigrationStatus(sc, "ad-guid-migration-status", "Running")
	if err != nil {
		return fmt.Errorf("unable to update migration status configmap: %v", err)
	}

	users, err := sc.Management.Users("").List(metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to fetch user list: %v", err)
	}

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
		logrus.Infof("[%v] Found AD user %v with GUID principalId %v, let's try a DN lookup", listAdUsersOperation, user.Name, principalId)
		guid, _, err := getExternalIdAndScope(principalId)
		if err != nil {
			// This really shouldn't be possible to hit, since isGuid will fail to parse anything that would
			// cause getExternalIdAndScope to choke on the input, but for maximum safety we'll handle it anyway.
			logrus.Errorf("[%v] Failed to extract ID from principal '%v', cannot process this user! (%v)", listAdUsersOperation, err, user.Name)
			continue
		}
		dn, err := findDistinguishedName(guid, adConfig)
		if err != nil {
			// TODO: Need to distinguish between missing user and failed LDAP connection. The error result should
			//   probably be typed accordingly. If the LDAP connection has failed, all future lookups will also fail,
			//   so we either need to re-establish the connection or die.
			// TODO: Missing upstream user case: What action should we take here?
			var apiError *httperror.APIError
			if errors.As(err, &apiError) && httperror.IsNotFound(apiError) {
				logrus.Infof("AD user does not exist, skipping migration for user: %v", err)
				continue
			}
			logrus.Errorf("[%v] failed to look up DN with: %v", listAdUsersOperation, err)
		} else {
			logrus.Infof("[%v] Local user with GUID '%v' maps to upstream user with DN: '%v'. Will proceed to migrate.", listAdUsersOperation, guid, dn)
			// Happy path: we have a local GUID user and an upstream DN to map them to. Make that change,
			// and then kick off all the relevant cleanup logic for this user's owned bindings.
			// TODO: said happy path
			dnPrincipal := activeDirectoryPrefix + dn
			err := migrateTokens(user.Name, dnPrincipal, sc, dryRun)
			if err != nil {
				return fmt.Errorf("unable to migrate token: %v", err)
			}
			err = migrateCRTB(guid, dnPrincipal, sc, dryRun)
			if err != nil {
				return fmt.Errorf("unable to migrate CRTB: %v", err)
			}
			err = migratePRTB(guid, dnPrincipal, sc, dryRun)
			if err != nil {
				return fmt.Errorf("unable to migrate PRTB: %v", err)
			}
			replaceGuidPrincipalWithDn(&user, dn)
			// yeah I don't trust that; debug time!
			logrus.Infof("[%v] User '%v' has new principals:", listAdUsersOperation, user.Name)
			for _, principalId := range user.PrincipalIDs {
				logrus.Infof("[%v]     '%v'", listAdUsersOperation, principalId)
			}
			logrus.Infof("[%v] WOULD SAVE HERE", listAdUsersOperation)
			// ... okay, moment of truth then. Let's save and see what happens!
			if dryRun {
				logrus.Infof("Dry Run: skipping user update %v", user.Name)
			} else {
				_, err = sc.Management.Users("").Update(&user)
				if err != nil {
					logrus.Errorf("[%v] Failed to save modified user '%v' with: %v", listAdUsersOperation, user.Name, err)
				}
			}
		}
	}
	err = updateMigrationStatus(sc, "ad-guid-migration-status", "Finished")
	if err != nil {
		return fmt.Errorf("unable to update migration status configmap: %v", err)
	}
	return nil
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

	return err
}
