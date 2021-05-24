package com.xdv.client.wallet;

public class SignResponse {
    private String publicKey;
    private String publicKey2;
    private String signature;
    private String digest;
    private String type;
    private String error;

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getDigest() {
        return digest;
    }

    public void setDigest(String digest) {
        this.digest = digest;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getPublicKey2() {
        return publicKey2;
    }

    public void setPublicKey2(String publicKey2) {
        this.publicKey2 = publicKey2;
    }
}
