#!/usr/bin/env bash
set -e

#
# Copyright 2022 ForgeRock AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

FORGEOPS_DIR=$(PWD)/tmp/forgeops
SCRIPTS_DIR=$(PWD)/scripts
CUSTOM_OVERLAY_DIR=$(PWD)/forgeops/overlay
CONFIG_PROFILE=cdk

if [[ -z "$NAMESPACE" || -z "$FQDN" || -z "$CLUSTER" || -z "$ZONE" || -z "$PROJECT" ]]; then
  echo "NAMESPACE, FQDN, CLUSTER, ZONE and PROJECT variables must be set"
exit 1
fi

echo "====================================================="
echo "Environment variables"
echo "====================================================="
echo "PROJECT=$PROJECT"
echo "CLUSTER=$CLUSTER"
echo "ZONE=$ZONE"
echo "NAMESPACE=$NAMESPACE"
echo "FQDN=$FQDN"

echo "====================================================="
echo "Clone Things and ForgeOps"
echo "====================================================="
rm -rf "$FORGEOPS_DIR" && mkdir -p "$FORGEOPS_DIR" && cd "$FORGEOPS_DIR"
git clone https://github.com/ForgeRock/forgeops.git .

cp -rf "$CUSTOM_OVERLAY_DIR"/* "$FORGEOPS_DIR"

gcloud container clusters get-credentials $CLUSTER --zone $ZONE --project $PROJECT

kubectl create namespace $NAMESPACE || true
kubens $NAMESPACE

cd $FORGEOPS_DIR/bin
./forgeops build amster --config-profile $CONFIG_PROFILE
./forgeops build am --config-profile $CONFIG_PROFILE
./forgeops build idm --config-profile $CONFIG_PROFILE
./forgeops install --cdk --fqdn $FQDN

kubectl cp $SCRIPTS_DIR/apply_schema.sh ds-idrepo-0:/tmp
kubectl exec ds-idrepo-0 -- /bin/bash -c "/tmp/apply_schema.sh"
