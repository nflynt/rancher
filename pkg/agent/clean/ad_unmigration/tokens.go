package ad_unmigration

import (
	"fmt"

	"github.com/rancher/rancher/pkg/auth/tokens"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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
				workunit.activeDirectoryTokens = append(workunit.activeDirectoryTokens, token)
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

func migrateTokens(workunit *migrateUserWorkUnit, sc *config.ScaledContext, dryRun bool) error {
	tokenInterface := sc.Management.Tokens("")
	dnPrincipalID := activeDirectoryPrefix + workunit.distinguishedName
	for _, userToken := range workunit.activeDirectoryTokens {
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
