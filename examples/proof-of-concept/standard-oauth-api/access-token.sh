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

function oauthRegister() {
  # Standard OAuth 2.0 dynamic client registration request
  echo $(curl --silent \
  --request POST "http://$FQDN/am/oauth2/realms/root/register" \
  --header "Content-Type: application/json" \
  --data "{ \"software_statement\": \"$1\"}")
}

function oauthToken() {
  # Standard OAuth 2.0 access token request
  echo $(curl --silent \
  --request POST "http://$FQDN/am/oauth2/realms/root/access_token" \
  --data "grant_type=client_credentials" \
  --data "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer" \
  --data "client_assertion=$1" \
  --data "scope=publish subscribe fr:idm:*" )
}

function thingsRegister() {
  # Request to register the thing by using a software statement
  regResponse=$(curl --silent \
  --request POST "http://$FQDN/am/json/authenticate?authIndexType=service&authIndexValue=oauth2-reg-tree" \
  --header "Content-Type: application/json" \
  --header "Accept-API-Version: resource=2.0, protocol=1.0" \
  --data-raw "{
       \"callbacks\": [
           {
               \"type\": \"HiddenValueCallback\",
               \"output\": [
                   {
                       \"name\": \"id\",
                       \"value\": \"software_statement\"
                   }
               ],
               \"input\": [
                   {
                       \"name\": \"IDToken1\",
                       \"value\": \"$1\"
                   }
               ]
           }
       ]}")
  ssoToken=$(jq -r '.tokenId' <(echo $regResponse))

  # Request the things attributes using the SSO token
  echo $(curl --silent \
  --request GET "http://$FQDN/am/json/things/*" \
  --header "Accept-API-Version: protocol=2.0,resource=1.0" \
  --header "Content-Type: application/json" \
  --header "Cookie: iPlanetDirectoryPro=${ssoToken}")
}

function thingsToken() {
  # Request to authenticate the thing by using a bearer JWT
  authResponse=$(curl --silent \
  --request POST "http://$FQDN/am/json/authenticate?authIndexType=service&authIndexValue=oauth2-auth-tree" \
  --header "Content-Type: application/json" \
  --header "Accept-API-Version: resource=2.0, protocol=1.0" \
  --data-raw "{
       \"callbacks\": [
           {
               \"type\": \"HiddenValueCallback\",
               \"output\": [
                   {
                       \"name\": \"id\",
                       \"value\": \"client_assertion\"
                   }
               ],
               \"input\": [
                   {
                       \"name\": \"IDToken1\",
                       \"value\": \"$1\"
                   }
               ]
           }
       ]}")
  ssoToken=$(jq -r '.tokenId' <(echo $authResponse))

  # Request the access token via the things endpoint
  echo $(curl --silent \
  --request POST "http://$FQDN/am/json/things/*?_action=get_access_token" \
  --header "Accept-API-Version: protocol=2.0,resource=1.0" \
  --header "Content-Type: application/json" \
  --header "Cookie: iPlanetDirectoryPro=${ssoToken}" \
  --data-raw '{
      "scope":["publish", "subscribe", "fr:idm:*"]
  }')
}

FQDN=
if [ -n "$1" ]; then
  FQDN=$1
  echo "Setting FQDN: $FQDN"
fi

# Register the thing and build the bearer JWT
cd things
software_statement=$(go run ./cmd/software-statement)
echo "---"
echo "Software statement:"
echo $software_statement

oauthRegisterResponse=$(echo $(oauthRegister $software_statement))
echo "---"
echo "OAuth 2.0 Dynamic Registration response:"
echo $oauthRegisterResponse
oauthClientID=$(jq -r '.client_id' <(echo $oauthRegisterResponse))

thingsRegisterResponse=$(echo $(thingsRegister $software_statement))
echo "---"
echo "Things Registration response:"
echo $thingsRegisterResponse
thingsClientID=$(jq -r '._id' <(echo $thingsRegisterResponse))

oauthClientAssertion=$(go run ./cmd/jwt-bearer-token -fqdn $FQDN -clientID $oauthClientID)
echo "---"
echo "OAuth 2.0 client assertion:"
echo $oauthClientAssertion

thingsClientAssertion=$(go run ./cmd/jwt-bearer-token -fqdn $FQDN -clientID $thingsClientID)
echo "---"
echo "Things client assertion:"
echo $thingsClientAssertion

oauthTokenResponse=$(echo $(oauthToken $oauthClientAssertion))
echo "---"
echo "OAuth 2.0 Access Token response:"
echo $oauthTokenResponse

thingsTokenResponse=$(echo $(thingsToken $thingsClientAssertion))
echo "---"
echo "Things Access Token response:"
echo $thingsTokenResponse
exit

#accessToken=$(jq -r '.access_token' <(echo $tokenResponse))
#echo "Access token: $accessToken"

#accessToken=$(jq -r '.access_token' <(echo $(thingsEndpoint $oauthClientAssertion)))

# NOTE: the following will only work if the things endpoint has been used
# get information about the current session
loginInfo=$(curl --silent --request GET "https://$FQDN/openidm/info/login" \
--header "authorization: Bearer $accessToken")

frId=$(echo ${loginInfo}| jq -r '.authenticationId')
echo "FR Id = $frId"


attributesResponse=$(curl --silent --request GET "https://$FQDN/openidm/managed/thing/$frId?_fields=thingProperties" \
--header "authorization: Bearer $accessToken")
echo "${attributesResponse}"
