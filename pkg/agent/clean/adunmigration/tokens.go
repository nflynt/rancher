package adunmigration

import (
	"fmt"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rancher/rancher/pkg/auth/tokens"
	"github.com/rancher/rancher/pkg/types/config"
)

func collectTokens(workunits *[]migrateUserWorkUnit, sc *config.ScaledContext) error {
	tokenInterface := sc.Management.Tokens("")
	tokenList, err := tokenInterface.List(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("[%v] unable to fetch token objects: %v", migrateAdUserOperation, err)
		return err
	}

	adWorkUnitsByPrincipal, duplicateLocalWorkUnitsByPrincipal := principalsToMigrate(workunits)

	for _, token := range tokenList.Items {
		if index, exists := adWorkUnitsByPrincipal[token.UserPrincipal.Name]; exists {
			if workUnitContainsName(&(*workunits)[index], token.UserID) {
				(*workunits)[index].activeDirectoryTokens = append((*workunits)[index].activeDirectoryTokens, token)
			} else {
				logrus.Warnf("[%v] found token for user with guid-based principal '%v' and name '%v', but no user object with that name matches the GUID or its associated DN. refusing to process",
					identifyAdUserOperation, token.UserPrincipal.Name, token.UserID)
			}
		} else if index, exists = duplicateLocalWorkUnitsByPrincipal[token.UserPrincipal.Name]; exists {
			if workUnitContainsName(&(*workunits)[index], token.UserID) {
				(*workunits)[index].duplicateLocalTokens = append((*workunits)[index].duplicateLocalTokens, token)
			} else {
				logrus.Warnf("[%v] found token for user with guid-based principal '%v' and name '%v', but no user object with that name matches the GUID or its associated DN. refusing to process",
					identifyAdUserOperation, token.UserPrincipal.Name, token.UserID)
			}
		}
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
				// Uncommonly, old tokens can expire during script execution. If this happens a token we collect may
				// be missing by the time we get around to processing the migration. Treat this as a soft error and
				// resume processing the remainder of the tokens.
				logrus.Warnf("[%v] token %s no longer exists: %v", migrateTokensOperation, userToken.Name, err)
				continue
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
