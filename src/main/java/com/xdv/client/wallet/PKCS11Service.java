package com.xdv.client.wallet;


import java.awt.*;
import java.security.*;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.*;
import eu.europa.esig.dss.enumerations.*;
import eu.europa.esig.dss.model.*;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.*;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.PasswordInputCallback;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
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
import java.util.List;
import java.util.Set;

public class PKCS11Service {

    private static String OS = System.getProperty("os.name").toLowerCase();

    private Module module;

    public PKCS11Service() {
    }


    public static boolean isWindows() {

        return (OS.indexOf("win") >= 0);

    }

    public static boolean isMac() {

        return (OS.indexOf("mac") >= 0);

    }

    public static boolean isUnix() {

        return (OS.indexOf("nix") >= 0 || OS.indexOf("nux") >= 0 || OS.indexOf("aix") > 0);

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

    private String getDriver() {
        if (PKCS11Service.isUnix()) {
            return "/usr/lib/libaetpkss.so";
        } else if (PKCS11Service.isMac()) {
            return "/usr/local/lib/libaetpkss.dylib";
        } else if (PKCS11Service.isWindows()) {
            return "C:\\Windows\\SysWOW64\\aetpksse.dll";
        }
        return "";
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
            byte[] cer1 = ((X509PublicKeyCertificate) certs[0]).getValue().getByteArrayValue();
            byte[] cer2 = ((X509PublicKeyCertificate) certs[1]).getValue().getByteArrayValue();

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream inCert1 = new ByteArrayInputStream(cer1);
            X509Certificate certificate1 = (X509Certificate) certFactory.generateCertificate(inCert1);

            InputStream inCert2 = new ByteArrayInputStream(cer2);
            X509Certificate certificate2 = (X509Certificate) certFactory.generateCertificate(inCert2);
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


    public SignResponse signPdfWithToken(int tokenIndex, String pin, byte[] data) throws TokenException, NoSuchAlgorithmException, CertificateException, CMSException, InvalidKeyException, NoSuchProviderException, SignatureException, InvalidKeySpecException, IOException {

        // tag::demo[]
        DSSDocument signedDocument;
        final String tspServer = "http://tsp.pki.gob.pa/tsr";
        OnlineTSPSource tspSource = new OnlineTSPSource(tspServer);
        tspSource.setDataLoader(new TimestampDataLoader()); // uses the specific content-type

        SignatureValue signatureValue;

        try (Pkcs11SignatureToken token = new Pkcs11SignatureToken(this.getDriver(), new PasswordInputCallback() {
            @Override
            public char[] getPassword() {
                return pin.toCharArray();
            }
        }, 0)) {


            List<DSSPrivateKeyEntry> keys = token.getKeys();
            DSSPrivateKeyEntry privateKey = keys.get(0);

            // Preparing parameters for the PAdES signature
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            // We choose the level of the signature (-B, -T, -LT, -LTA).
            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

            // We set the signing certificate
            parameters.setSigningCertificate(privateKey.getCertificate());
            // We set the certificate chain
            parameters.setCertificateChain(privateKey.getCertificateChain());

// Initialize visual signature and configure
            SignatureImageParameters imageParameters = new SignatureImageParameters();
            // set an image
            imageParameters.setImage(new FileDocument("src/main/resources/xdv.png"));
            // the origin is the left and top corner of the page
            imageParameters.setxAxis(200);
            imageParameters.setyAxis(400);
            imageParameters.setWidth(300);
            imageParameters.setHeight(200);
            // end::parameters-configuration[]

            // tag::font[]
            // Initialize text to generate for visual signature
         //   DSSFont font = new DSSFileFont(getClass().getResourceAsStream("/fonts/OpenSansRegular.ttf"));
            // end::font[]
            // tag::text[]
            // Instantiates a SignatureImageTextParameters object
            SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
            // Allows you to set a DSSFont object that defines the text style (see more information in the section "Fonts usage")
            // textParameters.setFont(font);
            // Defines the text content
            textParameters.setText("My visual signature \n #1");
            // Defines the color of the characters
            textParameters.setTextColor(Color.BLUE);
            // Defines the background color for the area filled out by the text
            textParameters.setBackgroundColor(Color.YELLOW);
            // Defines a padding between the text and a border of its bounding area
            textParameters.setPadding(20);
            // Set textParameters to a SignatureImageParameters object
            imageParameters.setTextParameters(textParameters);
            // end::text[]
            // tag::textImageCombination[]
            // Specifies a text position relatively to an image (Note: applicable only for joint image+text visible signatures).
            // Thus with _SignerPosition.LEFT_ value, the text will be placed on the left side,
            // and image will be aligned to the right side inside the signature field
            textParameters.setSignerTextPosition(SignerTextPosition.LEFT);
            // Specifies a horizontal alignment of a text with respect to its area
            textParameters.setSignerTextHorizontalAlignment(SignerTextHorizontalAlignment.RIGHT);
            // Specifies a vertical alignment of a text block with respect to a signature field area
            textParameters.setSignerTextVerticalAlignment(SignerTextVerticalAlignment.TOP);
            // end::textImageCombination[]
            // tag::sign[]
            parameters.setImageParameters(imageParameters);

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            // Create PAdESService for signature
            PAdESService service = new PAdESService(commonCertificateVerifier);
            // tag::custom-factory[]
            service.setPdfObjFactory(new PdfBoxNativeObjectFactory());
            service.setTspSource(tspSource);
            InMemoryDocument mem = new InMemoryDocument();
            // Get the SignedInfo segment that need to be signed.
            mem.setBytes(data);
            DSSDocument timestamped  =   service.timestamp(mem, new PAdESTimestampParameters());
            ToBeSigned dataToSign = service.getDataToSign(timestamped, parameters);

//            ToBeSigned toBeSigned = new ToBeSigned(data);
//            signatureValue = token.sign(toBeSigned, DigestAlgorithm.SHA256, keys.get(0));

            // This function obtains the signature value for signed information using the
            // private key and specified algorithm
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            signatureValue = token.sign(dataToSign, digestAlgorithm, privateKey);


            // We invoke the xadesService to sign the document with the signature value obtained in
            // the previous step.
            service.setTspSource(tspSource);
            signedDocument = service.signDocument(mem, parameters, signatureValue);
            // end::sign[]

            // end::demo[]

        }catch (Exception e){
            throw e ;
        }

        final DigestAlgorithm digestAlgorithm = DigestAlgorithm.SHA256;
        final byte[] toDigest = data;
        final byte[] digestValue = DSSUtils.digest(digestAlgorithm, toDigest);
        //    TimeStampToken tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);
//
//
//        System.out.println(tsBinary.getTimeStampInfo().getPolicy().toString());
//        System.out.println(DSSUtils.toHex(tsBinary.getTimeStampInfo().getMessageImprintDigest()));

        SignResponse response = new SignResponse();
        response.setSignature(Base64URL.encode((signatureValue.getValue())).toJSONString());
        signedDocument.setMimeType(MimeType.PDF);
        signedDocument.save("xdv.pdf");
        System.out.println(signedDocument.getAbsolutePath());
        return response;
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
//            TimeStampToken tsBinary = tspSource.getTimeStampResponse(digestAlgorithm, digestValue);
//
//
//            System.out.println(tsBinary.getTimeStampInfo().getPolicy().toString());
//            System.out.println(DSSUtils.toHex(tsBinary.getTimeStampInfo().getMessageImprintDigest()));

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
