package com.xdv.client.wallet;


import java.security.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.*;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import iaik.pkcs.pkcs11.*;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import iaik.pkcs.pkcs11.wrapper.PKCS11Exception;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.tsp.TimeStampToken;
import org.springframework.boot.SpringApplication;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Iterator;
import java.util.Set;

public class PKCS11Service {

    private static String OS = System.getProperty("os.name").toLowerCase();

    private Module module;

    public PKCS11Service(){
    }


    public static boolean isWindows() {

        return (OS.indexOf("win") >= 0);

    }

    public static boolean isMac() {

        return (OS.indexOf("mac") >= 0);

    }

    public static boolean isUnix() {

        return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0 );

    }


    public void initialize() throws TokenException, IOException {
        if (PKCS11Service.isUnix()) {
            this.module = Module.getInstance("/usr/lib/libaetpkss.so");
        } else if (PKCS11Service.isMac()) {
            this.module = Module.getInstance("/usr/local/lib/libaetpkss.dylib");
        } else if (PKCS11Service.isWindows()) {
                            this.module = Module.getInstance("C:\\Windows\\SysWOW64\\aetpksse.dll");
        }

        this.module.initialize(new DefaultInitializeArgs());
    }

    public Slot[] getSlots() throws TokenException {
       return this.module.getSlotList(true);
    }

    public Token getToken(int tokenIndex) throws TokenException {
        Slot[] slots = this.module.getSlotList(true);
        return slots[tokenIndex].getToken();
    }

    private void getTSP() {

    }

    public SignResponse getPublicKey(int tokenIndex, String pin) throws TokenException, NoSuchAlgorithmException, CertificateException, CMSException, InvalidKeyException, NoSuchProviderException, SignatureException {

        Slot[] slots = this.module.getSlotList(true);
        Token token = slots[tokenIndex].getToken();

        Session session = this.openReadWriteSession(token, pin);

        X509PublicKeyCertificate searchTemplate2 = new X509PublicKeyCertificate();
//        searchTemplate2.getId().setB;
        session.findObjectsInit(searchTemplate2);
        // find first
        PKCS11Object[] certs = session.findObjects(2);
        session.findObjectsFinal();


        if (certs.length > 0) {
            byte[] cer1 = ((X509PublicKeyCertificate)certs[0]).getValue().getByteArrayValue();
            byte[] cer2 = ((X509PublicKeyCertificate)certs[1]).getValue().getByteArrayValue();

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream inCert1 = new ByteArrayInputStream(cer1);
            X509Certificate certificate1 = (X509Certificate)certFactory.generateCertificate(inCert1);

            InputStream inCert2 = new ByteArrayInputStream(cer2);
            X509Certificate certificate2 = (X509Certificate)certFactory.generateCertificate(inCert2);
            String pem = DSSUtils.convertToPEM(new CertificateToken(certificate1));
            String pem2 = DSSUtils.convertToPEM(new CertificateToken(certificate2));

            SignResponse response = new SignResponse();
            String temp = Base64.getEncoder().encodeToString(certificate1.getPublicKey().getEncoded());
            String temp2 = Base64.getEncoder().encodeToString(certificate1.getPublicKey().getEncoded());

            response.setPublicKey(temp);
            response.setPublicKey2(pem);
            return response;
        } else {
            return new SignResponse();
        }
    }

    public SignResponse signWithToken(int tokenIndex, String pin, byte[] data) throws TokenException, NoSuchAlgorithmException, CertificateException, CMSException, InvalidKeyException, NoSuchProviderException, SignatureException, InvalidKeySpecException {

        Slot[] slots = this.module.getSlotList(true);
        Token token = slots[tokenIndex].getToken();

        Session session = this.openReadWriteSession(token, pin);

        final long mechCode = PKCS11Constants.CKM_SHA256_RSA_PKCS;

        RSAPrivateKey searchTemplate = new RSAPrivateKey();
        searchTemplate.getSign().setBooleanValue(true);
        session.findObjectsInit(searchTemplate);
        // find first
        PKCS11Object[] foundSignatureKeyObjects = session.findObjects(2);
        session.findObjectsFinal();


        X509PublicKeyCertificate searchTemplate2 = new X509PublicKeyCertificate();
//        searchTemplate2.getId().setB;
        session.findObjectsInit(searchTemplate2);
        // find first
        PKCS11Object[] certs = session.findObjects(2);
        session.findObjectsFinal();

        X509PublicKeyCertificate certificate = new X509PublicKeyCertificate();
        if (foundSignatureKeyObjects.length > 0) {
            Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);

            Key key = (Key) foundSignatureKeyObjects[0];
            session.signInit(signatureMechanism, key);
            byte[] signature = session.sign(data);

            byte[] cer1 = ((X509PublicKeyCertificate)certs[0]).getValue().getByteArrayValue();
            byte[] cer2 = ((X509PublicKeyCertificate)certs[1]).getValue().getByteArrayValue();

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream inCert1 = new ByteArrayInputStream(cer1);
            X509Certificate certificate1 = (X509Certificate)certFactory.generateCertificate(inCert1);

            InputStream inCert2 = new ByteArrayInputStream(cer2);
            X509Certificate certificate2 = (X509Certificate)certFactory.generateCertificate(inCert2);
            String pem = DSSUtils.convertToPEM(new CertificateToken(certificate1));

            RSAPublicKeySpec spec = new RSAPublicKeySpec(
                    ((java.security.interfaces.RSAPublicKey)certificate1.getPublicKey()).getModulus(),
                    ((java.security.interfaces.RSAPublicKey)certificate1.getPublicKey()).getPublicExponent());

            KeyFactory factory = KeyFactory.getInstance("RSA");

            PublicKey pub = factory.generatePublic(spec);
            Signature rsaVerify = Signature.getInstance("SHA256withRSA", "BC");
            rsaVerify.initVerify(pub);
            rsaVerify.update(data);
            rsaVerify.verify(signature);


            final String tspServer = "http://tsp.pki.gob.pa/tsr";
            OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
            tspSource.setDataLoader(new TimestampDataLoader()); // uses the specific content-type

            final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
            final byte[] toDigest = data;
            final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
            TimeStampToken tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);


            System.out.println(tsBinary.getTimeStampInfo().getPolicy().toString());
            System.out.println(DSSUtils.toHex(tsBinary.getTimeStampInfo().getMessageImprintDigest()));

            SignResponse response = new SignResponse();
            response.setSignature(Base64URL.encode((signature)).toJSONString());
            return response;
        } else {
            return new SignResponse();
        }
    }


    public SignResponse signJWT(int tokenIndex, String pin, byte[] data) throws TokenException, NoSuchAlgorithmException, CertificateException, CMSException, InvalidKeyException, NoSuchProviderException, SignatureException, ParseException, JOSEException {

        Slot[] slots = this.module.getSlotList(true);
        Token token = slots[tokenIndex].getToken();

        Session session = this.openReadWriteSession(token, pin);

        final long mechCode = PKCS11Constants.CKM_SHA256_RSA_PKCS;

        RSAPrivateKey searchTemplate = new RSAPrivateKey();
        searchTemplate.getSign().setBooleanValue(true);
        session.findObjectsInit(searchTemplate);
        // find first
        PKCS11Object[] foundSignatureKeyObjects = session.findObjects(1);
        session.findObjectsFinal();

        X509PublicKeyCertificate searchTemplate2 = new X509PublicKeyCertificate();
//        searchTemplate2.getId().setB;
        session.findObjectsInit(searchTemplate2);
        // find first
        PKCS11Object[] certs = session.findObjects(2);
        session.findObjectsFinal();

        X509PublicKeyCertificate certificate = new X509PublicKeyCertificate();
        if (foundSignatureKeyObjects.length > 0) {
            String aa = new String(data);
            String a = aa.split("\\.")[0];
            String   b  = aa.split("\\.")[1];
            SignedJWT signedJWT = new SignedJWT(
                    Base64URL.from(a),Base64URL.from(b),Base64URL.encode(""));

            signedJWT.sign(
                    new JWSSigner() {
                        @Override
                        public Base64URL sign(JWSHeader header, byte[] signingInput) throws JOSEException {
                            Mechanism signatureMechanism = null;
                            try {
                                signatureMechanism = getSupportedMechanism(token, mechCode);
                            } catch (TokenException e) {
                                e.printStackTrace();
                            }
                            MessageDigest md = null;
                            try {
                                md = MessageDigest.getInstance("SHA-256");


                                
                            } catch (NoSuchAlgorithmException e) {
                                e.printStackTrace();
                            }
                            byte[] hashValue = md.digest(signingInput);


                            Key key = (Key) foundSignatureKeyObjects[0];
                            byte[] pub = ((X509PublicKeyCertificate)certs[0]).getValue().getByteArrayValue();
                            try {
                                session.signInit(signatureMechanism, key);
                            } catch (TokenException e) {
                                e.printStackTrace();
                            }
                            byte[] signature = new byte[0];
                            try {
                                signature = session.sign(hashValue);
                            } catch (TokenException e) {
                                e.printStackTrace();
                            }

                            return Base64URL.encode(signature);
                        }

                        @Override
                        public Set<JWSAlgorithm> supportedJWSAlgorithms() {
                            return null;
                        }

                        @Override
                        public JCAContext getJCAContext() {
                            return null;
                        }
                    }
            );


            byte[] cer1 = ((X509PublicKeyCertificate)certs[0]).getValue().getByteArrayValue();
            byte[] cer2 = ((X509PublicKeyCertificate)certs[1]).getValue().getByteArrayValue();

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream inCert1 = new ByteArrayInputStream(cer1);
            X509Certificate certificate1 = (X509Certificate)certFactory.generateCertificate(inCert1);

            InputStream inCert2 = new ByteArrayInputStream(cer2);
            X509Certificate certificate2 = (X509Certificate)certFactory.generateCertificate(inCert2);
            String pem = DSSUtils.convertToPEM(new CertificateToken(certificate1));

            String sig = signedJWT.getSignature().toJSONString();
                    SignResponse response = new SignResponse();
            response.setPublicKey(pem);
            response.setSignature(sig);
            return response;
        } else {
            return new SignResponse();
        }
    }

    protected Session openReadWriteSession(Token token, String pin)
            throws TokenException {
        return this.openAuthorizedSession(token, true,
                pin == null ? null : pin.toCharArray());
    }

    /**
     * Opens an authorized session for the given token. If the token requires the
     * user to login for private operations, the method loggs in the user.
     *
     * @param token
     *          The token to open a session for.
     * @param rwSession
     *          If the session should be a read-write session. This may be
     *          Token.SessionReadWriteBehavior.RO_SESSION or
     *          Token.SessionReadWriteBehavior.RW_SESSION.
     * @param pin
     *          PIN.
     * @return The selected token or null, if no token is available or the user
     *         canceled the action.
     * @exception TokenException
     *              If listing the tokens failed.
     * @exception IOException
     *              If writing a user prompt failed or if reading user input
     *              failed.
     */
    public static Session openAuthorizedSession(
            Token token, boolean rwSession, char[] pin)
            throws TokenException {
        if (token == null) {
            throw new NullPointerException("Argument \"token\" must not be null.");
        }

        Session session = token.openSession(Token.SessionType.SERIAL_SESSION,
                rwSession, null, null);

        TokenInfo tokenInfo = token.getTokenInfo();
        if (tokenInfo.isLoginRequired()) {
            if (tokenInfo.isProtectedAuthenticationPath()) {
                System.out.print(
                        "Please enter the user-PIN at the PIN-pad of your reader.");
                System.out.flush();
                // the token prompts the PIN by other means; e.g. PIN-pad
                session.login(Session.UserType.USER, null);
            } else {
                try {
                    session.login(Session.UserType.USER, pin);
                } catch (PKCS11Exception ex) {
                    if (ex.getErrorCode() != PKCS11Constants.CKR_USER_ALREADY_LOGGED_IN) {
                        throw ex;
                    }
                }
            }
        }

        return session;
    }

    protected void assertSupport(Token token, Mechanism mech)
            throws TokenException {
        if (supports(token, mech.getMechanismCode())) {
            return;
        } else {
            String msg = "Mechanism " + mech.getName() + " is not supported";
            throw new TokenException(msg);
        }
    }

    protected Mechanism getSupportedMechanism(Token token, long mechCode)
            throws TokenException {
        Mechanism mech = Mechanism.get(mechCode);
        assertSupport(token, mech);
        return mech;
    }
    public static boolean supports(Token token, long mechCode)
            throws TokenException {
        for (Mechanism mech : token.getMechanismList()) {
            if (mech.getMechanismCode() == mechCode) {
                return true;
            }
        }
        return false;
    }

}
