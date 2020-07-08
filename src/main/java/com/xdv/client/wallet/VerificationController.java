package com.xdv.client.wallet;

import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.*;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.Reports;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cms.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.async.DeferredResult;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.util.Collection;
import java.util.Iterator;

import static org.springframework.web.bind.annotation.RequestMethod.*;


@RestController
public class VerificationController {

    private static final Logger log = LoggerFactory.getLogger(VerificationController.class);

    public String verifySignature(String name, String contentType, byte[] data, byte[] cert) throws CMSException {
        return verifySignature(name, contentType, data,  cert, null, false );
    }

    public String verifySignature(String name, String contentType, byte[] data, byte[] cert, byte[] contents, boolean  detached) throws CMSException {

        DSSDocument document;
        SignedDocumentValidator documentValidator = null;
        if (!detached) {
            // Here is the document to be validated (any kind of signature file)
            document = new InMemoryDocument(data, name);

            // We create an instance of DocumentValidator
            documentValidator = SignedDocumentValidator.fromDocument(document);
        }

        CertificateToken c = DSSUtils.loadCertificate(cert);

        CertificateVerifier cv = new CommonCertificateVerifier();

        CertificateValidator validator = CertificateValidator.fromCertificate(c);

        // Capability to download resources from AIA
        cv.setDataLoader(new CommonsDataLoader());

        // Capability to request OCSP Responders
        cv.setOcspSource(new OnlineOCSPSource());

        // Capability to download CRL
        cv.setCrlSource(new OnlineCRLSource());

        validator.setCertificateVerifier(cv);
        CertificateReports reports = validator.validate();

        if  (detached){
            String b  = new String(data);
            b = b.replaceAll("-----BEGIN PKCS7-----", "")
                    .replaceAll("\r\n","")
                    .replaceAll("-----END PKCS7-----","");


            CMSProcessable signedContent = new CMSProcessableByteArray(contents);
            InputStream is = new ByteArrayInputStream(Base64.decode(b));

            //Pass them both to CMSSignedData constructor
            CMSSignedData cms = new CMSSignedData(signedContent, is);

            CMSSignedDocument cmsSignedDocument = new CMSSignedDocument(cms);
            documentValidator = SignedDocumentValidator.fromDocument(cmsSignedDocument);
        }
        // We add the certificate verifier (which allows to verify and trust certificates)
        documentValidator.setCertificateVerifier(cv);

        Reports reports1 = documentValidator.validateDocument();


        return reports1.getXmlSimpleReport();
    }


    @CrossOrigin(
            exposedHeaders = {"Authorization","Location"},
            allowedHeaders = {"Authorization", "Cache-Control", "Content-Type"},
            methods = {POST,  PUT, OPTIONS},
            origins = {"http://localhost:8080","https://xdvmessaging.auth2factor.com"}
    )
    @RequestMapping(
            method = {POST, PUT, OPTIONS},
            value = "/xdv_verify")
    public DeferredResult<ResponseEntity<?>> verifySignedPdf(
            @RequestBody VerifyPayload payload) {
        DeferredResult<ResponseEntity<?>> deferredResult = new DeferredResult<ResponseEntity<?>>();
        ResponseEntity.BodyBuilder internalErr = ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON);

        try {
//
//            if (!token.equals("12345")) {
//                deferredResult.setResult(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
//                return deferredResult;
//            }
            String res;
            if (payload.getContents() == null) {
                res = this.verifySignature(
                        payload.getFilename(),
                        null,
                        payload.getSignature().getBytes(),
                        Base64.decode(payload.getCertificate())
                );
            } else {
                res = this.verifySignature(
                        payload.getFilename(),
                        null,
                        payload.getSignature().getBytes(),
                        Base64.decode(payload.getCertificate()),
                        Base64.decode(payload.getContents()),
                        true
                );
            }
            if (res != null) {
                deferredResult.setResult(ResponseEntity.ok(res));
            } else {
                deferredResult.setResult(ResponseEntity
                        .status(HttpStatus.BAD_REQUEST)
                        .build());
            }
        }
        catch (Exception ex){
            log.error("err", ex);
            deferredResult.setResult(internalErr.body(""));
        }

        return deferredResult;
    }

    private String getFileChecksum(byte[] fileContent) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(fileContent);
            return DatatypeConverter.printHexBinary(md.digest()).toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }


    public static boolean verifyDetachedPKCS7(byte[] cert, byte[] detachedSignature,byte[] content) throws IOException, CMSException, NoSuchAlgorithmException, NoSuchProviderException, CertStoreException, CertificateExpiredException, CertificateNotYetValidException {

        String b  = new String(detachedSignature);
        b = b.replaceAll("-----BEGIN PKCS7-----", "")
                .replaceAll("\r\n","")
                .replaceAll("-----END PKCS7-----","");
        boolean result = false;
        Security.addProvider(new BouncyCastleProvider());


        try{

            //Create a CMSProcessable object, specify any encoding, I have used mine
//Create a InputStream object
            CMSProcessable signedContent = new CMSProcessableByteArray(content);
            InputStream is = new ByteArrayInputStream(Base64.decode(b));
//Pass them both to CMSSignedData constructor
            CMSSignedData cms = new CMSSignedData(signedContent, is);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            InputStream inCert = new ByteArrayInputStream(cert);
            X509Certificate certificate = (X509Certificate)certFactory.generateCertificate(inCert);
            SignerInformationStore signers = cms.getSignerInfos();
            Collection c = signers.getSigners();
            Iterator it = c.iterator();
            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                X509CertificateHolder h = new X509CertificateHolder(certificate.getEncoded());
                result = signer.getSID().match(h);
                // result = a;
                // result=signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(h));
            }

        }catch(Exception e){
            e.printStackTrace();
            result = false;
        }
        return result;
    }

    // https://stackoverflow.com/questions/8243566/verifying-detached-signature-with-bc/9261365#9261365
}
