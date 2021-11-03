/*
 * Copyright 2021 ForgeRock AS
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

package com.example.forgetv;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;

import org.json.JSONObject;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;

public class InfoActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_info);
        TextView idTxt = findViewById(R.id.textViewInfo);
        idTxt.setText(getResources().getString(R.string.thing_id));
        TextView jwkTxt = findViewById(R.id.textJWK);
        try {
            // read public key from keystore
            KeyStore keyStore = KeyStore.getInstance(AbstractJWTSigner.PROVIDER);
            keyStore.load(null);
            PublicKey publicKey = keyStore.getCertificate(AbstractJWTSigner.KEY_ALIAS).getPublicKey();
            ECKey esKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                    .keyID(getResources().getString(R.string.jwt_kid))
                    .keyUse(KeyUse.SIGNATURE)
                    .build();

            // write key in a JWK Set
            String jwkSet = String.format("{\"keys\":[%s]}", new JSONObject(esKey.toJSONObject()));
            jwkTxt.setText(jwkSet);

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            jwkTxt.setText(e.getMessage());
        }

    }

    public void refresh(View view){
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
    }
}