package com.xdv.client.wallet;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.objects.RSAPrivateKey;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.IOException;

public class PKCS11Service {

    private Module module;

    public PKCS11Service(){
    }
    public void initialize() throws TokenException, IOException {
        this.module = Module.getInstance("/usr/local/lib/softhsm/libsofthsm2.so");
        this.module.initialize(new DefaultInitializeArgs());
    }

    public Slot[] getSlots() throws TokenException {
       return this.module.getSlotList(true);
    }

    public Token getToken(int tokenIndex) throws TokenException {
        Slot[] slots = this.module.getSlotList(true);
        return slots[tokenIndex].getToken();
    }

    public byte[] signWithToken(int tokenIndex, byte[] data) throws TokenException {
        Slot[] slots = this.module.getSlotList(true);
        Token token = slots[tokenIndex].getToken();
        Session session = token.openSession(
                Token.SessionType.SERIAL_SESSION,
                Token.SessionReadWriteBehavior.RO_SESSION,
                null,
                null
        );

        RSAPrivateKey searchTemplate = new RSAPrivateKey();
        searchTemplate.getSign().setBooleanValue(true);
        session.findObjectsInit(searchTemplate);
        Object[] matchingKeys;
        java.security.interfaces.RSAPrivateKey signatureKey = null;
        if ((matchingKeys = session.findObjects(1)).length > 0) {
            signatureKey = (java.security.interfaces.RSAPrivateKey)matchingKeys[0];
        } else  {
        }
        session.findObjectsFinal();

        Mechanism signatureMechanism = Mechanism.get(PKCS11Constants.CKM_SHA1_RSA_PKCS);
        session.signInit(signatureMechanism, (Key) signatureKey);
        byte[] signature = session.sign(data);
        return signature;
    }
}
