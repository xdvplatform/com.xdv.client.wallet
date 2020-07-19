/*
 *
 * Copyright (c) 2019 Lijun Liao
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

package demo.pkcs.pkcs11.wrapper.signatures;

import java.security.Security;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import iaik.pkcs.pkcs11.objects.PublicKey;

/**
 * Signature test base
 *
 * @author Lijun Liao
 */
public class SignatureTestBase extends TestBase {

    public static void addProvider() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    protected boolean jceVerifySignature(String algorithm, java.security.PublicKey publicKey,
                                         byte[] data, byte[] signatureValue) throws Exception {
        // verify with JCE
        // jcePublicKey = generateJCEPublicKey(publicKey);
        Signature signature = Signature.getInstance(algorithm, "BC");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureValue);
    }

}