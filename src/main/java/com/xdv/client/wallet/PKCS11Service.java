package com.xdv.client.wallet;
import iaik.pkcs.pkcs11.*;
import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.objects.*;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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

    public byte[] signWithToken(int tokenIndex, byte[] data) throws TokenException, NoSuchAlgorithmException {
        Slot[] slots = this.module.getSlotList(true);
        Token token = slots[tokenIndex].getToken();
        Session session = token.openSession(
                Token.SessionType.SERIAL_SESSION,
                Token.SessionReadWriteBehavior.RO_SESSION,
                null,
                null
        );
        final long mechCode = PKCS11Constants.CKM_RSA_PKCS;

        RSAPrivateKey searchTemplate = new RSAPrivateKey();
        searchTemplate.getSign().setBooleanValue(true);
        session.findObjectsInit(searchTemplate);
        // find first
        PKCS11Object[] foundSignatureKeyObjects = session.findObjects(1);
        session.findObjectsFinal();

        if (foundSignatureKeyObjects.length > 0) {
            Mechanism signatureMechanism = getSupportedMechanism(token, mechCode);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashValue = md.digest(data);


            session.signInit(signatureMechanism, (Key) foundSignatureKeyObjects[0]);
            byte[] signature = session.sign(hashValue);
            return signature;
        } else {
            return "".getBytes();
        }

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
