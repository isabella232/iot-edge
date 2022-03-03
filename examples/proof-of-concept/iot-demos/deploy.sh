#!/usr/bin/env bash
set -e

#
# Copyright 2021-2022 ForgeRock AS
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
IOT_EDGE_DIR=$(PWD)/tmp/iot-edge
CUSTOM_OVERLAY_DIR=$(PWD)/forgeops/overlay
SECRETS_DIR=$(PWD)/forgeops/secrets
CONNECTOR_DIR=$(PWD)/../gcp-iot/gcp-iot-core-connector
CONFIG_PROFILE=cdk

if [[ -z "$NAMESPACE" || -z "$FQDN" || -z "$CLUSTER" || -z "$ZONE" || -z "$PROJECT" ]]; then
  echo "NAMESPACE, FQDN, CLUSTER, ZONE and PROJECT variables must be set"
exit 1
fi

if [ -n "$1" ]; then
  PLATFORM_PASSWORD=$1
  echo "Overriding platform password: $PLATFORM_PASSWORD"
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
echo "Build the connector"
echo "====================================================="
cd $CONNECTOR_DIR
mvn clean install

echo "====================================================="
echo "Clone Things and ForgeOps"
echo "====================================================="
rm -rf "$IOT_EDGE_DIR" && mkdir -p "$IOT_EDGE_DIR" && cd "$IOT_EDGE_DIR"
git clone https://github.com/ForgeRock/iot-edge.git .
git checkout release/v7.1.0
rm -rf "$FORGEOPS_DIR" && mkdir -p "$FORGEOPS_DIR" && cd "$FORGEOPS_DIR"
git clone https://github.com/ForgeRock/forgeops.git .
git checkout release/7.1.0

echo "====================================================="
echo "Overlay custom files"
echo "====================================================="
cp -rf "$CUSTOM_OVERLAY_DIR"/* "$FORGEOPS_DIR"
cp -rf "$SECRETS_DIR"/* "$IOT_EDGE_DIR/deployments/forgeops/secrets"
sed -i '' "s/&{NAMESPACE}/$NAMESPACE/g" "$FORGEOPS_DIR/kustomize/overlay/7.0/all/kustomization.yaml"
sed -i '' "s/&{FQDN}/$FQDN/g" "$FORGEOPS_DIR/kustomize/overlay/7.0/all/kustomization.yaml"
sed -i '' "s/&{NAMESPACE}/$NAMESPACE/g" "$IOT_EDGE_DIR/deployments/forgeops/secrets/iot-secrets.yaml"
mkdir -p "$FORGEOPS_DIR/docker/7.0/idm/connectors"
mkdir -p "$FORGEOPS_DIR/docker/7.0/idm/lib"
cp -f "$CONNECTOR_DIR/target/gcp-iot-core-connector-0.1.jar" "$FORGEOPS_DIR/docker/7.0/idm/connectors/gcp-iot-core-connector-0.1.jar"
cp -f $CONNECTOR_DIR/target/lib/* $FORGEOPS_DIR/docker/7.0/idm/lib

echo "====================================================="
echo "Create '$NAMESPACE' namespace"
echo "====================================================="
kubectl create namespace $NAMESPACE || true
kubens $NAMESPACE

echo "====================================================="
echo "Configure Skaffold to use default repo"
echo "====================================================="
skaffold config set default-repo gcr.io/$PROJECT -k gke_$PROJECT_$ZONE_$CLUSTER

echo "====================================================="
echo "Clean out existing pods for '$NAMESPACE' namespace"
echo "====================================================="
skaffold delete

echo "====================================================="
echo "Initialise '$CONFIG_PROFILE' configuration profile"
echo "====================================================="
"$FORGEOPS_DIR"/bin/config.sh init --profile $CONFIG_PROFILE --version 7.0
"$FORGEOPS_DIR"/bin/config.sh init --profile $CONFIG_PROFILE --component ds --version 7.0

echo "====================================================="
echo "Apply IoT secrets"
echo "====================================================="
if [ -n "$PLATFORM_PASSWORD" ]; then
  kubectl delete secret am-env-secrets || true
  kubectl create secret generic am-env-secrets --from-literal=AM_PASSWORDS_AMADMIN_CLEAR=$PLATFORM_PASSWORD
fi
kubectl apply --filename $IOT_EDGE_DIR/deployments/forgeops/secrets/iot-secrets.yaml
kubectl create --filename $IOT_EDGE_DIR/deployments/forgeops/secrets/iot-secret-agent-configuration.yaml

echo "====================================================="
echo "Run the platform"
echo "====================================================="
skaffold run

echo "====================================================="
echo "~~~ Platform login details ~~~"
$FORGEOPS_DIR/bin/print-secrets
echo "====================================================="
