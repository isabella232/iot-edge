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
	"time"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TODO issuer and subject may be different. Issuer must be the ID of the thing and subject must be the client_id of
// the OAuth client. If dynamic registration resulted in a generated client_id then these might not have the same values.
func jwtBearerToken(key crypto.Signer, subject, audience, kid string) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("kid", kid)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		return "", err
	}
	return jwt.Signed(sig).
		Claims(jwt.Claims{
			Issuer:   subject,
			Subject:  subject,
			Audience: []string{audience},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		}).CompactSerialize()
}

func main() {
	var (
		amurl   = flag.String("amurl", "", "The AM URL of the ForgeOps deployment")
		thingID = flag.String("thingID", "4Y1SL65848Z411439", "The ID of the thing.")
		clientID = flag.String("clientID", "", "The ID of the dynamically registered OAuth 2 client.")
	)
	flag.Parse()

	if *amurl == "" {
		log.Fatal("AM URL must be provided")
	}
	//if *clientID == "" {
	//	log.Fatal("clientID must be provided")
	//}

	store := secrets.Store{Path: "things.secrets"}
	signer, _ := store.Signer(*thingID)
	keyID, _ := thing.JWKThumbprint(signer)
	signedJWT, err := jwtBearerToken(signer, *clientID, *amurl+"/oauth2/access_token", keyID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(signedJWT)
}
