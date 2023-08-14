package ad_unmigration

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	"github.com/rancher/rancher/pkg/auth/providers/common/ldap"
	v3client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Rancher 2.7.5 serialized binary GUIDs from LDAP using this pattern, so this
// is what we should match. Notably this differs from Active Directory GUID
// strings, which have dashes and braces as delimiters.
var validRancherGuidPattern = regexp.MustCompile("^[0-9a-f]+$")

type LdapErrorNotFound struct{}

// Error provides a string representation of an LdapErrorNotFound
func (e LdapErrorNotFound) Error() string {
	return "ldap query returned no results"
}

// LdapFoundDuplicateGUID indicates either a configuration error or
// a corruption on the Active Directory side. In theory it should never
// be possible when talking to a real Active Directory server, but just
// in case we detect and handle it anyway.
type LdapFoundDuplicateGUID struct{}

// Error provides a string representation of an LdapErrorNotFound
func (e LdapFoundDuplicateGUID) Error() string {
	return "ldap query returned multiple users for the same GUID"
}

type LdapConnectionPermanentlyFailed struct{}

// Error provides a string representation of an LdapConnectionPermanentlyFailed
func (e LdapConnectionPermanentlyFailed) Error() string {
	return "ldap search failed to connect after exhausting maximum retry attempts"
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
		return "", LdapFoundDuplicateGUID{}
	}

	entry := result.Entries[0]

	return entry.DN, nil
}

func findDistinguishedNameWithRetries(guid string, lConn *ldapv3.Conn, adConfig *v3.ActiveDirectoryConfig) (string, error) {
	// These settings range from 2 seconds for minor blips to around a full minute for repeated failures
	backoff := wait.Backoff{
		Duration: 2 * time.Second,
		Factor:   1.5, // duration multiplied by this for each retry
		Jitter:   0.1, // random variance, just in case other parts of rancher are using LDAP while we work
		Steps:    10,  // number of retries before we consider this failure to be permanent
	}

	distinguishedName := ""
	err := wait.ExponentialBackoff(backoff, func() (bool, error) {
		var err error
		distinguishedName, err = findDistinguishedName(guid, lConn, adConfig)
		if err == nil || errors.Is(err, LdapErrorNotFound{}) || errors.Is(err, LdapFoundDuplicateGUID{}) {
			return true, err
		}
		// any other error type almost certainly indicates a connection failure. Close and re-open the connection
		// before retrying
		logrus.Warnf("[%v] LDAP connection failed: '%v', retrying...", migrateAdUserOperation, err)
		lConn.Close()
		lConn, err = ldapConnection(adConfig)
		// If that also fails, we're definitely having a rough time of things.
		if err != nil {
			return true, LdapConnectionPermanentlyFailed{}
		}

		return false, err
	})

	return distinguishedName, err
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

func isGUID(principalID string) bool {
	parts := strings.Split(principalID, "://")
	if len(parts) != 2 {
		logrus.Errorf("[%v] failed to parse invalid PrincipalID: %v", identifyAdUserOperation, principalID)
		return false
	}
	return validRancherGuidPattern.MatchString(parts[1])
}
