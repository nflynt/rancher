package ad_unmigration

import (
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/types/config"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// principalsToMigrate collects workunits whose resources we wish to migrate into two groups:
//
//	adWorkUnitsByPrincipal - resources should be migrated to an ActiveDirectory principal with a Distinguished Name
//	duplicateLocalWorkUnitsByPrincipal - resources should be migrated to the local ID of the original (kept) user
func principalsToMigrate(workunits *[]migrateUserWorkUnit) (adWorkUnitsByPrincipal map[string]int, duplicateLocalWorkUnitsByPrincipal map[string]int) {
	// first build a map of guid-principalid -> work unit, which will make the following logic more efficient
	adWorkUnitsByPrincipal = map[string]int{}
	duplicateLocalWorkUnitsByPrincipal = map[string]int{}

	for i, workunit := range *workunits {
		adWorkUnitsByPrincipal[activeDirectoryPrefix+workunit.guid] = i
		for j := range workunit.duplicateUsers {
			duplicateLocalWorkUnitsByPrincipal[activeDirectoryPrefix+workunit.guid] = j
			duplicateLocalWorkUnitsByPrincipal[activeDirectoryPrefix+workunit.distinguishedName] = j
			duplicateLocalWorkUnitsByPrincipal[localPrefix+workunit.duplicateUsers[j].Name] = j
		}
	}

	return adWorkUnitsByPrincipal, duplicateLocalWorkUnitsByPrincipal
}

func collectCRTBs(workunits *[]migrateUserWorkUnit, sc *config.ScaledContext) error {
	crtbInterface := sc.Management.ClusterRoleTemplateBindings("")
	crtbList, err := crtbInterface.List(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("[%v] unable to fetch CRTB objects: %v", migrateAdUserOperation, err)
		return err
	}

	adWorkUnitsByPrincipal, duplicateLocalWorkUnitsByPrincipal := principalsToMigrate(workunits)

	for _, crtb := range crtbList.Items {
		if index, exists := adWorkUnitsByPrincipal[crtb.UserPrincipalName]; exists {
			if workUnitContainsName(&(*workunits)[index], crtb.UserName) {
				(*workunits)[index].activeDirectoryCRTBs = append((*workunits)[index].activeDirectoryCRTBs, crtb)
			} else {
				logrus.Warnf("[%v] found CRTB for user with guid-based principal '%v' and name '%v', but no user object with that name matches the GUID or its associated DN. refusing to process",
					identifyAdUserOperation, crtb.UserPrincipalName, crtb.UserName)
			}
		} else if index, exists = duplicateLocalWorkUnitsByPrincipal[crtb.UserPrincipalName]; exists {
			if workUnitContainsName(&(*workunits)[index], crtb.UserName) {
				(*workunits)[index].duplicateLocalCRTBs = append((*workunits)[index].duplicateLocalCRTBs, crtb)
			} else {
				logrus.Warnf("[%v] found CRTB for user with guid-based principal '%v' and name '%v', but no user object with that name matches the GUID or its associated DN. refusing to process",
					identifyAdUserOperation, crtb.UserPrincipalName, crtb.UserName)
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

	adWorkUnitsByPrincipal, duplicateLocalWorkUnitsByPrincipal := principalsToMigrate(workunits)

	for _, prtb := range prtbList.Items {
		if index, exists := adWorkUnitsByPrincipal[prtb.UserPrincipalName]; exists {
			if workUnitContainsName(&(*workunits)[index], prtb.UserName) {
				(*workunits)[index].activeDirectoryPRTBs = append((*workunits)[index].activeDirectoryPRTBs, prtb)
			} else {
				logrus.Warnf("[%v] found PRTB for user with guid-based principal '%v' and name '%v', but no user object with that name matches the GUID or its associated DN. refusing to process",
					identifyAdUserOperation, prtb.UserPrincipalName, prtb.UserName)
			}
		} else if index, exists = duplicateLocalWorkUnitsByPrincipal[prtb.UserPrincipalName]; exists {
			if workUnitContainsName(&(*workunits)[index], prtb.UserName) {
				(*workunits)[index].duplicateLocalPRTBs = append((*workunits)[index].duplicateLocalPRTBs, prtb)
			} else {
				logrus.Warnf("[%v] found PRTB for user with guid-based principal '%v' and name '%v', but no user object with that name matches the GUID or its associated DN. refusing to process",
					identifyAdUserOperation, prtb.UserPrincipalName, prtb.UserName)
			}
		}
	}

	return nil
}

func collectGRBs(workunits *[]migrateUserWorkUnit, sc *config.ScaledContext) error {
	grbInterface := sc.Management.GlobalRoleBindings("")
	grbList, err := grbInterface.List(metav1.ListOptions{})
	if err != nil {
		logrus.Errorf("[%v] unable to fetch GRB objects: %v", migrateAdUserOperation, err)
		return err
	}

	duplicateLocalWorkUnitsByName := map[string]int{}

	for _, workunit := range *workunits {
		for j := range workunit.duplicateUsers {
			duplicateLocalWorkUnitsByName[workunit.duplicateUsers[j].Name] = j
		}
	}

	for _, grb := range grbList.Items {
		if index, exists := duplicateLocalWorkUnitsByName[grb.UserName]; exists {
			(*workunits)[index].duplicateLocalGRBs = append((*workunits)[index].duplicateLocalGRBs, grb)
		}
	}

	return nil
}

func migrateCRTBs(workunit *migrateUserWorkUnit, sc *config.ScaledContext, dryRun bool) error {
	crtbInterface := sc.Management.ClusterRoleTemplateBindings("")
	// First convert all GUID-based CRTBs to their equivalent Distinguished Name variants
	dnPrincipalID := activeDirectoryPrefix + workunit.distinguishedName
	for _, oldCrtb := range workunit.activeDirectoryCRTBs {
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
	for _, oldPrtb := range workunit.activeDirectoryPRTBs {
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

func migrateGRBs(workunit *migrateUserWorkUnit, sc *config.ScaledContext, dryRun bool) error {
	grbInterface := sc.Management.GlobalRoleBindings("")

	for _, oldGrb := range workunit.duplicateLocalGRBs {
		if dryRun {
			logrus.Infof("[%v] DRY RUN: would migrate GRB '%v' from duplicate local user '%v' to original user '%v'"+
				"Additionally, labels %v and %v will be added. These contain the name of the previous GRB and indicate that this GRB has been migrated.",
				migrateGrbsOperation, oldGrb.Name, oldGrb.UserName, workunit.originalUser.Name, migrationPreviousName, adGUIDMigrationLabel)
		} else {
			newLabels := oldGrb.Labels
			if newLabels == nil {
				newLabels = make(map[string]string)
			}
			newLabels[migrationPreviousName] = oldGrb.Name
			newLabels[adGUIDMigrationLabel] = migratedLabelValue

			newGrb := &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:         "",
					GenerateName: "grb-",
					Annotations:  oldGrb.Annotations,
					Labels:       newLabels,
				},
				GlobalRoleName:     oldGrb.GlobalRoleName,
				GroupPrincipalName: oldGrb.GroupPrincipalName,
				UserName:           workunit.originalUser.Name,
			}
			_, err := grbInterface.Create(newGrb)
			if err != nil {
				return fmt.Errorf("[%v] unable to create new GRB: %w", migrateGrbsOperation, err)
			}
			err = sc.Management.GlobalRoleBindings("").Delete(oldGrb.Name, &metav1.DeleteOptions{})
			if err != nil {
				return fmt.Errorf("[%v] unable to delete GRB: %w", migrateGrbsOperation, err)
			}
		}
	}
	return nil
}