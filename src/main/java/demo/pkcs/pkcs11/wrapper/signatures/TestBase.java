// Copyright (c) 2002 Graz University of Technology. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. The end-user documentation included with the redistribution, if any, must
//    include the following acknowledgment:
//
//    "This product includes software developed by IAIK of Graz University of
//     Technology."
//
//    Alternately, this acknowledgment may appear in the software itself, if and
//    wherever such third-party acknowledgments normally appear.
//
// 4. The names "Graz University of Technology" and "IAIK of Graz University of
//    Technology" must not be used to endorse or promote products derived from
//    this software without prior written permission.
//
// 5. Products derived from this software may not be called "IAIK PKCS Wrapper",
//    nor may "IAIK" appear in their name, without prior written permission of
//    Graz University of Technology.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
// WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
// ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package demo.pkcs.pkcs11.wrapper.signatures;

import java.io.InputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Properties;
import java.util.Random;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.DSAPrivateKey;
import iaik.pkcs.pkcs11.objects.DSAPublicKey;
import iaik.pkcs.pkcs11.objects.ECPrivateKey;
import iaik.pkcs.pkcs11.objects.ECPublicKey;
import iaik.pkcs.pkcs11.objects.Key.KeyType;
import iaik.pkcs.pkcs11.objects.KeyPair;
import iaik.pkcs.pkcs11.objects.PublicKey;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.objects.RSAPublicKey;
import iaik.pkcs.pkcs11.wrapper.Functions;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

public class TestBase {

    // plen: 2048, qlen: 256
    public static final String DSA_P =
            "E13AC60336C29FAF1B48393D80C74B781E15E23E3F59F0827190FF016720A8E0"
                    + "DAC2D4FF699EBA2196E1B9815ECAE0506441A4BC4DA97E97F2723A808EF6B634"
                    + "3968906137B04B23F6540FC4B9D7C0A46635B6D52AEDD08347370B9BE43A7222"
                    + "807655CB5ED480F4C66128357D0E0A2C62785DC38160645661FA569ADCE46D3B"
                    + "3BFAB114613436242855F5717143D51FB365972F6B8695C2186CBAD1E8C5B4D3"
                    + "1AD70876EBDD1C2191C5FB6C4804E0D38CBAA054FC7AFD25E0F2735F726D8A31"
                    + "DE97431BFB6CF1AD563811830131E7D5E5117D92389406EF436A8077E69B8795"
                    + "18436E33A9F221AB3A331680D0345B316F5BEBDA8FBF70612BEC734272E760BF";

    public static final String DSA_Q =
            "9CF2A23A8F95FEFB0CA67212991AC172FDD3F4D70401B684C3E4223D46D090E5";

    public static final String DSA_G =
            "1CBEF6EEB9E73C5997BF64CA8BCC33CDC6AFC5601B86FDE1B0AC4C34066DFBF9"
                    + "9B80CCE264C909B32CF88CE09CB73476C0A6E701092E09C93507FE3EBD425B75"
                    + "8AE3C5E3FDC1076AF237C5EF40A790CF6555EB3408BCEF212AC5A1C125A7183D"
                    + "24935554C0D258BF1F6A5A6D05C0879DB92D32A0BCA3A85D42F9B436AE97E62E"
                    + "0E30E53B8690D8585493D291969791EA0F3B062645440587C031CD2880481E0B"
                    + "E3253A28EFFF3ACEB338A2FE4DB8F652E0FDA277268B73D5E532CF9E4E2A1CAB"
                    + "738920F760012DD9389F35E0AA7C8528CE173934529397DABDFAA1E77AF83FAD"
                    + "629AC102596885A06B5C670FFA838D37EB55FE7179A88F6FF927B37E0F827726";

    private static String modulePath;

    private static String modulePin;

    private static Integer slotIndex;

    private static Module module;

    private static RuntimeException initException;

    private static int speedThreads;

    private static String speedDuration;

    private static SecureRandom random = new SecureRandom();

    protected Logger LOG = LoggerFactory.getLogger(getClass());

    static {
        Properties props = new Properties();
        try {
            props.load(TestBase.class.getResourceAsStream("/pkcs11.properties"));
            modulePath = props.getProperty("module.path");
            modulePin = props.getProperty("module.pin");
            String str = props.getProperty("module.slotIndex");
            slotIndex = (str == null) ? null : Integer.parseInt(str);
            module = Module.getInstance(modulePath);

            speedThreads = Integer.getInteger("speed.threads", 2);
            speedDuration = System.getProperty("speed.duration", "3s");
            module.initialize(null);
        } catch (Exception ex) {
            initException = new RuntimeException(ex);
        }
    }

    protected char[] getModulePin() {
        return modulePin.toCharArray();
    }

    protected Token getNonNullToken() throws TokenException {
        Token token = getToken();
        if (token == null) {
            LOG.error("We have no token to proceed. Finished.");
            throw new TokenException("No token found!");
        }
        return token;
    }

    protected Token getToken() throws TokenException {
        if (initException != null) {
            throw initException;
        }
        return demo.pkcs.pkcs11.wrapper.signatures.Util.selectToken(module, slotIndex);
    }

    protected Module getModule() {
        if (initException != null) {
            throw initException;
        }
        return module;
    }

    protected Session openReadOnlySession(Token token)
            throws TokenException {
        return Util.openAuthorizedSession(token, false,
                modulePin == null ? null : modulePin.toCharArray());
    }

    protected Session openReadOnlySession() throws TokenException {
        return openReadOnlySession(getToken());
    }

    protected Session openReadWriteSession(Token token)
            throws TokenException {
        return Util.openAuthorizedSession(token, true,
                modulePin == null ? null : modulePin.toCharArray());
    }

    protected Session openReadWriteSession() throws TokenException {
        return openReadWriteSession(getToken());
    }

    protected String getSpeedTestDuration() {
        return speedDuration;
    }

    protected int getSpeedTestThreads() {
        return speedThreads;
    }

    protected InputStream getResourceAsStream(String path) {
        return getClass().getResourceAsStream(path);
    }

    public static byte[] randomBytes(int len) {
        byte[] ret = new byte[len];
        random.nextBytes(ret);
        return ret;
    }

    protected void assertSupport(Token token, Mechanism mech)
            throws TokenException {
        if (Util.supports(token, mech.getMechanismCode())) {
            return;
        } else {
            String msg = "Mechanism " + mech.getName() + " is not supported";
            LOG.error(msg);
            throw new TokenException(msg);
        }
    }

    protected Mechanism getSupportedMechanism(Token token, long mechCode)
            throws TokenException {
        Mechanism mech = Mechanism.get(mechCode);
        assertSupport(token, mech);
        return mech;
    }

    protected KeyPair generateRSAKeypair(
            Token token, Session session, int keysize, boolean inToken)
            throws TokenException {
        Mechanism keyPairGenMechanism = getSupportedMechanism(token,
                PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
        RSAPublicKey oublicKeyTemplate = new RSAPublicKey();
        RSAPrivateKey privateKeyTemplate = new RSAPrivateKey();

        // set the general attributes for the public key
        oublicKeyTemplate.getModulusBits().setLongValue(Long.valueOf(1024));
        oublicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        byte[] id = new byte[20];
        new Random().nextBytes(id);
        oublicKeyTemplate.getId().setByteArrayValue(id);

        privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getToken().setBooleanValue(inToken);
        privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getId().setByteArrayValue(id);

        privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        oublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);

        // netscape does not set these attribute, so we do no either
        oublicKeyTemplate.getKeyType().setPresent(false);
        oublicKeyTemplate.getObjectClass().setPresent(false);
        privateKeyTemplate.getKeyType().setPresent(false);
        privateKeyTemplate.getObjectClass().setPresent(false);

        return session.generateKeyPair(keyPairGenMechanism,
                oublicKeyTemplate, privateKeyTemplate);
    }

    protected KeyPair generateECKeypair(
            Token token, Session session, byte[] ecParams, boolean inToken)
            throws TokenException {
        return generateECKeypair(PKCS11Constants.CKM_EC_KEY_PAIR_GEN,
                token, session, ecParams, inToken);
    }

    protected KeyPair generateEdDSAKeypair(
            Token token, Session session, byte[] ecParams, boolean inToken)
            throws TokenException {
        return generateECKeypair(PKCS11Constants.CKM_EC_EDWARDS_KEY_PAIR_GEN,
                token, session, ecParams, inToken);
    }

    private KeyPair generateECKeypair(long keyGenMechanism,
                                      Token token, Session session, byte[] ecParams, boolean inToken)
            throws TokenException {
        Mechanism keyPairGenMechanism = getSupportedMechanism(token,
                keyGenMechanism);
        ECPublicKey publicKeyTemplate = new ECPublicKey();
        ECPrivateKey privateKeyTemplate = new ECPrivateKey();

        // set the general attributes for the public key
        publicKeyTemplate.getEcdsaParams().setByteArrayValue(ecParams);
        publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);
        byte[] id = new byte[20];
        new Random().nextBytes(id);
        publicKeyTemplate.getId().setByteArrayValue(id);

        privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getToken().setBooleanValue(inToken);
        privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getId().setByteArrayValue(id);

        privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);

        // netscape does not set these attribute, so we do no either
        publicKeyTemplate.getKeyType().setPresent(false);
        publicKeyTemplate.getObjectClass().setPresent(false);
        privateKeyTemplate.getKeyType().setPresent(false);
        privateKeyTemplate.getObjectClass().setPresent(false);

        return session.generateKeyPair(keyPairGenMechanism,
                publicKeyTemplate, privateKeyTemplate);
    }

    protected KeyPair generateDSAKeypair(
            Token token, Session session, boolean inToken)
            throws TokenException {
        Mechanism keyPairGenMechanism = getSupportedMechanism(token,
                PKCS11Constants.CKM_DSA_KEY_PAIR_GEN);
        DSAPublicKey publicKeyTemplate = new DSAPublicKey();
        DSAPrivateKey privateKeyTemplate = new DSAPrivateKey();

        publicKeyTemplate.getPrime().setByteArrayValue(
                Functions.decodeHex(DSA_P));
        publicKeyTemplate.getSubprime().setByteArrayValue(
                Functions.decodeHex(DSA_Q));
        publicKeyTemplate.getBase().setByteArrayValue(
                Functions.decodeHex(DSA_G));
        publicKeyTemplate.getToken().setBooleanValue(Boolean.FALSE);

        byte[] id = new byte[20];
        new Random().nextBytes(id);
        publicKeyTemplate.getId().setByteArrayValue(id);

        privateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getToken().setBooleanValue(inToken);
        privateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
        privateKeyTemplate.getId().setByteArrayValue(id);

        privateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
        publicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);

        // netscape does not set these attribute, so we do no either
        publicKeyTemplate.getKeyType().setPresent(false);
        publicKeyTemplate.getObjectClass().setPresent(false);
        privateKeyTemplate.getKeyType().setPresent(false);
        privateKeyTemplate.getObjectClass().setPresent(false);

        return session.generateKeyPair(keyPairGenMechanism,
                publicKeyTemplate, privateKeyTemplate);
    }

    protected static java.security.PublicKey generateJCEPublicKey(
            PublicKey p11Key) throws InvalidKeySpecException {
        if (p11Key instanceof RSAPublicKey) {
            RSAPublicKey rsaP11Key = (RSAPublicKey) p11Key;
            byte[] expBytes = rsaP11Key.getPublicExponent().getByteArrayValue();
            BigInteger exp = new BigInteger(1, expBytes);

            byte[] modBytes = rsaP11Key.getModulus().getByteArrayValue();
            BigInteger mod = new BigInteger(1, modBytes);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(mod, exp);
            return KeyUtil.generateRSAPublicKey(keySpec);
        } else if (p11Key instanceof DSAPublicKey) {
            DSAPublicKey dsaP11Key = (DSAPublicKey) p11Key;

            BigInteger prime =
                    new BigInteger(1, dsaP11Key.getPrime().getByteArrayValue()); // p
            BigInteger subPrime =
                    new BigInteger(1, dsaP11Key.getSubprime().getByteArrayValue()); // q
            BigInteger base =
                    new BigInteger(1, dsaP11Key.getBase().getByteArrayValue()); // g
            BigInteger value =
                    new BigInteger(1, dsaP11Key.getValue().getByteArrayValue()); // y
            DSAPublicKeySpec keySpec =
                    new DSAPublicKeySpec(value, prime, subPrime, base);
            return KeyUtil.generateDSAPublicKey(keySpec);
        } else if (p11Key instanceof ECPublicKey) {
            ECPublicKey ecP11Key = (ECPublicKey) p11Key;
            long keyType = ecP11Key.getKeyType().getLongValue().longValue();
            byte[] ecParameters = ecP11Key.getEcdsaParams().getByteArrayValue();
            byte[] encodedPoint = DEROctetString.getInstance(
                    ecP11Key.getEcPoint().getByteArrayValue()).getOctets();

            if (keyType == KeyType.EC_EDWARDS || keyType == KeyType.EC_MONTGOMERY) {
                ASN1ObjectIdentifier algOid =
                        ASN1ObjectIdentifier.getInstance(ecParameters);
                SubjectPublicKeyInfo pkInfo = new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(algOid), encodedPoint);
                return KeyUtil.generatePublicKey(pkInfo);
            } else {
                return KeyUtil.createECPublicKey(ecParameters, encodedPoint);
            }
        } else {
            throw new InvalidKeySpecException(
                    "unknown publicKey class " + p11Key.getClass().getName());
        }
    } // method generatePublicKey

}