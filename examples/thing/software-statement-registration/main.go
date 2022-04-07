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
	"net/url"
	"os"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func popWithSoftwareStatementRegistration() (err error) {
	var (
		urlString = flag.String("url", "http://am.localtest.me:8080/am", "URL of AM or Gateway")
		realm     = flag.String("realm", "/", "AM Realm")
		audience  = flag.String("audience", "/", "JWT audience")
		authTree  = flag.String("tree", "iot-tree", "Authentication tree")
		thingName = flag.String("name", "", "Thing name")
		iss       = flag.String("iss", "https://soft-pub.example.com", "The software publisher issuer.")
	)
	flag.Parse()

	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}
	if *thingName == "" {
		*thingName = uuid.New().String()
	}

	softPubStore := secrets.Store{Path: "soft-pub.secrets"}
	softPubKey, _ := softPubStore.Signer(*iss)
	softPubKid, _ := thing.JWKThumbprint(softPubKey)
	softPubJWK, _ := jose.JSONWebKey{KeyID: softPubKid, Key: softPubKey.Public(), Algorithm: string(jose.ES256), Use: "sig"}.MarshalJSON()
	log.Println("Software publisher public key:")
	log.Println("{\"keys\": [" + string(softPubJWK) + "]}")

	thingStore := secrets.Store{}
	thingKey, _ := thingStore.Signer(*thingName)
	thingKid, _ := thing.JWKThumbprint(thingKey)
	thingJWK := jose.JSONWebKey{KeyID: thingKid, Key: thingKey.Public(), Algorithm: string(jose.ES256), Use: "sig"}
	ss, err := softwareStatement(softPubKey, thingJWK, softPubKid, thingKid, *iss)
	if err != nil {
		log.Fatal(err)
	}

	deviceBuilder := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		HandleCallbacksWith(callback.RegisterHandler{
			Audience:          *audience,
			ThingID:           *thingName,
			ThingType:         callback.TypeDevice,
			KeyID:             thingKid,
			Key:               thingKey,
			SoftwareStatement: ss,
		})

	fmt.Printf("Creating Thing %s... ", *thingName)
	device, err := deviceBuilder.Create()
	if err != nil {
		return err
	}
	fmt.Printf("Done\n")

	fmt.Printf("Requesting access token... ")
	tokenResponse, err := device.RequestAccessToken("publish")
	if err != nil {
		return err
	}
	fmt.Println("Done")
	token, err := tokenResponse.AccessToken()
	if err != nil {
		return err
	}
	fmt.Println("Access token:", token)
	expiresIn, err := tokenResponse.ExpiresIn()
	if err != nil {
		return err
	}
	fmt.Println("Expires in:", expiresIn)
	scopes, err := tokenResponse.Scope()
	if err != nil {
		return err
	}
	fmt.Println("Scope(s):", scopes)

	return nil
}

func softwareStatement(key crypto.Signer, clientJWK jose.JSONWebKey, softPubKid, thingKid, iss string) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("alg", "ES256")
	opts.WithHeader("kid", softPubKid)
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
		SoftwareID:   thingKid,
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
	// pipe debug to standard out
	thing.DebugLogger().SetOutput(os.Stdout)

	if err := popWithSoftwareStatementRegistration(); err != nil {
		log.Fatal(err)
	}
}
