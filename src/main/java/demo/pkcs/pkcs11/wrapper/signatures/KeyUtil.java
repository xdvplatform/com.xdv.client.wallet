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

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

/**
 * Key utility class.
 *
 * @author Lijun Liao
 */

public class KeyUtil {

    private static final Map<String, KeyFactory> KEY_FACTORIES = new HashMap<>();

    private KeyUtil() {
    }

    // CHECKSTYLE:SKIP
    public static DSAPublicKey generateDSAPublicKey(DSAPublicKeySpec keySpec)
            throws InvalidKeySpecException {
        KeyFactory kf = getKeyFactory("DSA");
        synchronized (kf) {
            return (DSAPublicKey) kf.generatePublic(keySpec);
        }
    }

    public static KeyFactory getKeyFactory(String algorithm)
            throws InvalidKeySpecException {
        String alg = algorithm.toUpperCase();
        if ("ECDSA".equals(alg)) {
            alg = "EC";
        }
        synchronized (KEY_FACTORIES) {
            KeyFactory kf = KEY_FACTORIES.get(algorithm);
            if (kf != null) {
                return kf;
            }

            try {
                kf = KeyFactory.getInstance(algorithm, "BC");
            } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
                throw new InvalidKeySpecException(
                        "could not find KeyFactory for " + algorithm
                                + ": " + ex.getMessage());
            }
            KEY_FACTORIES.put(algorithm, kf);
            return kf;
        }
    }

    public static PublicKey generatePublicKey(SubjectPublicKeyInfo pkInfo)
            throws InvalidKeySpecException {

        X509EncodedKeySpec keyspec;
        try {
            keyspec = new X509EncodedKeySpec(pkInfo.getEncoded());
        } catch (IOException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }
        ASN1ObjectIdentifier aid = pkInfo.getAlgorithm().getAlgorithm();

        String algorithm;
        if (PKCSObjectIdentifiers.rsaEncryption.equals(aid)) {
            algorithm = "RSA";
        } else if (X9ObjectIdentifiers.id_dsa.equals(aid)) {
            algorithm = "DSA";
        } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(aid)) {
            algorithm = "EC";
        } else {
            algorithm = null;
        }

        if (algorithm == null) {
            throw new InvalidKeySpecException("unsupported key algorithm: " + aid);
        }

        KeyFactory kf = getKeyFactory(algorithm);
        synchronized (kf) {
            return kf.generatePublic(keyspec);
        }
    }

    // CHECKSTYLE:SKIP
    public static RSAPublicKey generateRSAPublicKey(RSAPublicKeySpec keySpec)
            throws InvalidKeySpecException {
        KeyFactory kf = getKeyFactory("RSA");
        synchronized (kf) {
            return (RSAPublicKey) kf.generatePublic(keySpec);
        }
    }

    // CHECKSTYLE:SKIP
    public static ECPublicKey createECPublicKey(
            byte[] encodedAlgorithmIdParameters, byte[] encodedPoint)
            throws InvalidKeySpecException {

        ASN1Encodable algParams;
        if (encodedAlgorithmIdParameters[0] == 6) {
            algParams =
                    ASN1ObjectIdentifier.getInstance(encodedAlgorithmIdParameters);
        } else {
            algParams = X962Parameters.getInstance(encodedAlgorithmIdParameters);
        }
        AlgorithmIdentifier algId = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey, algParams);

        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, encodedPoint);
        X509EncodedKeySpec keySpec;
        try {
            keySpec = new X509EncodedKeySpec(spki.getEncoded());
        } catch (IOException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }

        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("EC", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            throw new InvalidKeySpecException(ex.getMessage(), ex);
        }
        return (ECPublicKey) kf.generatePublic(keySpec);
    }

}