package com.xdv.client.wallet;

public class SignPayload {
    private String data;
    private String pin;
    private int tokenIndex;

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getPin() {
        return pin;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public int getTokenIndex() {
        return tokenIndex;
    }

    public void setTokenIndex(int tokenIndex) {
        this.tokenIndex = tokenIndex;
    }
}
