package com.xdv.client.wallet;
import eu.europa.esig.dss.model.x509.CertificateToken;
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
import org.springframework.boot.SpringApplication;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Iterator;

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

    public SignResponse signWithToken(int tokenIndex, String pin, byte[] data) throws TokenException, NoSuchAlgorithmException, CertificateException, CMSException, InvalidKeyException, NoSuchProviderException, SignatureException {

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
            Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashValue = md.digest(data);

            Key key = (Key) foundSignatureKeyObjects[0];
            byte[] pub = ((X509PublicKeyCertificate)certs[0]).getValue().getByteArrayValue();
            session.signInit(signatureMechanism, key);
            byte[] signature = session.sign(hashValue);


            byte[] cer1 = ((X509PublicKeyCertificate)certs[0]).getValue().getByteArrayValue();
            byte[] cer2 = ((X509PublicKeyCertificate)certs[1]).getValue().getByteArrayValue();

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream inCert1 = new ByteArrayInputStream(cer1);
            X509Certificate certificate1 = (X509Certificate)certFactory.generateCertificate(inCert1);

            InputStream inCert2 = new ByteArrayInputStream(cer2);
            X509Certificate certificate2 = (X509Certificate)certFactory.generateCertificate(inCert2);
            String pem = DSSUtils.convertToPEM(new CertificateToken(certificate1));


            SignResponse response = new SignResponse();
            response.setPublicKey(pem);
            response.setSignature(Base64.getEncoder().encodeToString(signature));
            response.setDigest(Base64.getEncoder().encodeToString(hashValue));
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
