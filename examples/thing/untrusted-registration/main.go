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
)

func untrustedRegistration() (err error) {
	var (
		urlString = flag.String("url", "http://am.localtest.me:8080/am", "URL of AM or Gateway")
		realm     = flag.String("realm", "/", "AM Realm")
		audience  = flag.String("audience", "/", "JWT audience")
		authTree  = flag.String("tree", "iot-tree", "Authentication tree")
		thingName = flag.String("name", "", "Thing name")
	)
	flag.Parse()

	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}
	if *thingName == "" {
		*thingName = uuid.New().String()
	}

	thingStore := secrets.Store{}
	thingKey, _ := thingStore.Signer(*thingName)
	thingKid, _ := thing.JWKThumbprint(thingKey)

	deviceBuilder := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		HandleCallbacksWith(callback.RegisterHandler{
			Audience:  *audience,
			ThingID:   *thingName,
			ThingType: callback.TypeDevice,
			KeyID:     thingKid,
			Key:       thingKey,
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

func main() {
	// pipe debug to standard out
	thing.DebugLogger().SetOutput(os.Stdout)

	if err := untrustedRegistration(); err != nil {
		log.Fatal(err)
	}
}
