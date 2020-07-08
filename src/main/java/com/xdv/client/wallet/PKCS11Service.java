package com.xdv.client.wallet;
import iaik.pkcs.pkcs11.DefaultInitializeArgs;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;

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
}
