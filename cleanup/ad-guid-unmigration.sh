#!/bin/bash
# set -x
set -e

# Text to display in the banner
banner_text="This utility will go through all Rancher users and perform an Active Directory lookup using
the configured service account to get the user's distinguished name.  Next, it will perform lookups inside Rancher
for all the user's Tokens, ClusterRoleTemplateBindings, and ProjectRoleTemplateBindings.  If any of those objects,
including the user object itself are referencing a principalID based on the GUID of that user, those objects will be
updated to reference the distinguished name-based principalID (unless the utility is run with -dry-run, in that case
the only results are log messages indicating the changes that would be made by a run without that flag).

This utility will also detect and correct the case where a single ActiveDirectory GUID is mapped to multiple Rancher
users.  That condition was likely caused by a race in the original migration to use GUIDs and resulted in a second
Rancher user being created.  This caused Rancher logins to fail for the duplicated user.  The utility remedies
that situation by mapping any tokens and bindings to the original user before removing the newer user, which was
created in error.

It is also important to note that migration of ClusterRoleTemplateBindings and ProjectRoleTemplateBindings require
a delete/create operation rather than an update.  This will result in new object names for the migrated bindings.
A label with the former object name will be included in the migrated bindings.

It is recommended that you perform a Rancher backup prior to running this utility."

CLEAR='\033[0m'
RED='\033[0;31m'

# Location of the yaml to use to deploy the cleanup job
yaml_url=https://raw.githubusercontent.com/rancher/rancher/master/cleanup/ad-guid-unmigration.yaml

# 7200 is equal to one hour as the sleep is half a second
timeout=7200

# Agent image to use in the yaml file
agent_image="$1"

show_usage() {
  if [ -n "$1" ]; then
    echo -e "${RED}👉 $1${CLEAR}\n";
  fi
	echo -e "Usage: $0 [AGENT_IMAGE] [FLAGS]"
	echo "AGENT_IMAGE is a required argument"
	echo ""
	echo "Flags:"
	echo -e "\t-dry-run Display the resources that would will be updated without making changes"
    echo -e "\t-delete-missing Permanently remove user objects whose GUID cannot be found in Active Directory"
}

# Function to display text in a banner format
display_banner() {
    local text="$1"
    local border_char="="
    local text_width=$(($(tput cols)))
    local border=$(printf "%${text_width}s" | tr " " "$border_char")

    echo "$border"
    printf "%-${text_width}s \n" "$text"
    echo "$border"
}

display_banner "${banner_text}"
read -p "Do you want to continue? (y/n): " choice
if [[ ! $choice =~ ^[Yy]$ ]]; then
    echo "Exiting..."
    exit 0
fi

if [ $# -lt 1 ]
then
	show_usage "AGENT_IMAGE is a required argument"
	exit 1
fi

if [[ $1 == "-h" ||$1 == "--help" ]]
then
	show_usage
	exit 0
fi

# Pull the yaml and replace the agent_image holder with the passed in image
# yaml=$(curl --insecure -sfL $yaml_url | sed -e 's=agent_image='"$agent_image"'=')
# Except it isn't pushed anywhere useful yet, so instead read the local file
yaml=$(cat ad-guid-unmigration.yaml | sed -e 's=agent_image='"$agent_image"'=')

if [ "$2" = "-dry-run" ]
then
    # Uncomment the env var for dry-run mode
    yaml=$(sed -e 's/#dryrun // ' <<< "$yaml")
elif [ "$2" = "-delete-missing" ]
then
    # Instead uncomment the env var for missing user cleanup
    yaml=$(sed -e 's/#deletemissing // ' <<< "$yaml")
fi

echo "$yaml" | kubectl apply -f -

# Get the pod ID to tail the logs
pod_id=$(kubectl get pod -l job-name=cattle-cleanup-job -o jsonpath="{.items[0].metadata.name}")

declare -i count=0
until kubectl logs $pod_id -f
do
    if [ $count -gt $timeout ]
    then
        echo "Timout reached, check the job by running kubectl get jobs"
        exit 1
    fi
    sleep 0.5
    count+=1
done

# Cleanup after it completes successfully
echo "$yaml" | kubectl delete -f -
