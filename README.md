# com.xdv.client.wallet

## Java Client
Pkcs11 para registro público de Panamá cortesía de Industrias de Firmas Electronicas sa copyright 2020 a 2021. Enter the wu tang! 


## Using com.xdv.client.wallet

`com.xdv.client.wallet` is a websocket based Spring boot application. It has a signing API and verification API.


### Signing

To run the websocket, start the spring boot application and in `PKCS11Service` call the `initialize` method which will detect OS and load SafeSign drivers for Linux, Mac or Windows.


#### getSlots

Gets a list of hardware modules with PKCS#11 support

#### signWithToken

**Arguments

- **tokenIndex**: A number with 0 index representing the slot
- **pin**: Pin for the hardware module
- **data**: Binary to sign

**Returns a SignResponse object

- **publicKey**: The corresponding public key for the key pair
- **signature**: The signed binary data
- **digest**: Hash for the binary data
- **type**: Signature type
- **error**: Error message


Sample code

```java

  
   X509PublicKeyCertificate certificate = new X509PublicKeyCertificate();
  // If slot found then enable mechanism
  if (foundSignatureKeyObjects.length > 0) {
            Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);
            
            // 1. Create digest (hash) with SHA 256
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashValue = md.digest(data);

            Key key = (Key) foundSignatureKeyObjects[0];
            byte[] pub = ((X509PublicKeyCertificate)certs[0]).getValue().getByteArrayValue();
            
            // 2. Initialize keys and sign digest with session
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
            
            // 3. Registro Publico has 2 keys, we just return one

            // 4. You need to return public key, signature and digest, you'll need these three to be able to verify
            SignResponse response = new SignResponse();
            response.setPublicKey(pem);
            response.setSignature(Base64.getEncoder().encodeToString(signature));
            response.setDigest(Base64.getEncoder().encodeToString(hashValue));
            return response;
```




### Verification

### MIT licensed 
