/*
 * Copyright 2022 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func softwareStatement(key crypto.Signer, clientJWK jose.JSONWebKey, keyID, iss, clientName string) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("alg", "ES256")
	opts.WithHeader("kid", keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		return "", err
	}
	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{clientJWK},
	}
	jwtBuilder := jwt.Signed(signer).Claims(struct {
		Issuer       string             `json:"iss"`
		SoftwareID   string             `json:"software_id"`
		RedirectURIs []string           `json:"redirect_uris"`
		GrantTypes   []string           `json:"grant_types"`
		Scope        string             `json:"scope"`
		JWKS         jose.JSONWebKeySet `json:"jwks"`
	}{
		Issuer:       iss,
		SoftwareID:   clientName,
		RedirectURIs: []string{"https://client.example.com:8443/callback"},
		GrantTypes:   []string{"client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		Scope:        "publish subscribe fr:idm:*",
		JWKS:         keySet,
	})
	response, err := jwtBuilder.CompactSerialize()
	if err != nil {
		return "", err
	}
	return response, err
}

func main() {
	var (
		iss     = flag.String("iss", "https://soft-pub.example.com", "The software publisher issuer.")
		thingID = flag.String("thingID", "4Y1SL65848Z411439", "The ID of the thing for which this software statement is being prepared.")
	)
	flag.Parse()

	softPubStore := secrets.Store{Path: "soft-pub.secrets"}
	softPubKey, _ := softPubStore.Signer(*iss)
	softPubKid, _ := thing.JWKThumbprint(softPubKey)
	softPubJWK, _ := jose.JSONWebKey{KeyID: softPubKid, Key: softPubKey.Public(), Algorithm: string(jose.ES256), Use: "sig"}.MarshalJSON()
	log.Println("Software publisher public key:")
	log.Println("{\"keys\": [" + string(softPubJWK) + "]}")

	thingStore := secrets.Store{Path: "things.secrets"}
	thingKey, _ := thingStore.Signer(*thingID)
	thingKid, _ := thing.JWKThumbprint(thingKey)
	thingJWK := jose.JSONWebKey{KeyID: thingKid, Key: thingKey.Public(), Algorithm: string(jose.ES256), Use: "sig"}
	ss, err := softwareStatement(softPubKey, thingJWK, softPubKid, *iss, *thingID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(ss)
}
