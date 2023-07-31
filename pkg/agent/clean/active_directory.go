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
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"strings"
)

const (
	listAdUsersOperation   = "list-ad-users"
	migrateAdUserOperation = "migrate-ad-user"
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
		return "", fmt.Errorf("cannot locate user information for %s", search.Filter)
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

	users, err := sc.Management.Users("").List(metav1.ListOptions{})

	for _, user := range users.Items {
		logrus.Infof("[%v] Found user with name: %v", listAdUsersOperation, user.Name)
		for _, principalId := range user.PrincipalIDs {
			logrus.Infof("[%v] Has principal ID: %v", listAdUsersOperation, principalId)
		}
		logrus.Infof("[%v] UID: %v, username: %v", listAdUsersOperation, user.UID, user.Username)
		if isAdUser(&user) {
			logrus.Infof("[%v] Appears to be an AD user!", listAdUsersOperation)
			principalId := adPrincipalId(&user)
			if isGuid(principalId) {
				// TODO: guard on dry run!
				logrus.Infof("[%v] Found AD user %v with GUID principalId %v, let's try a DN lookup", listAdUsersOperation, user.Name, principalId)
				guid, _, err := getExternalIdAndScope(principalId)
				if err != nil {
					logrus.Errorf("[%v] somehow failed to extract ID from principal!? %v", listAdUsersOperation, err)
				} else {
					dn, err := findDistinguishedName(guid, adConfig)
					if err != nil {
						logrus.Errorf("[%v] failed to look up DN with: %v", listAdUsersOperation, err)
					} else {
						logrus.Infof("[%v] GOT DISTINGUISHED NAME: %v", listAdUsersOperation, dn)
					}
				}
			}
		}
	}

	return nil
}

func isAdUser(user *v3.User) bool {
	for _, principalId := range user.PrincipalIDs {
		if strings.HasPrefix(principalId, "activedirectory_user://") {
			return true
		}
	}
	return false
}

func adPrincipalId(user *v3.User) string {
	for _, principalId := range user.PrincipalIDs {
		if strings.HasPrefix(principalId, "activedirectory_user://") {
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
