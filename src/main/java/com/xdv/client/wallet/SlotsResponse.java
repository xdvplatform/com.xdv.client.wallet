package com.xdv.client.wallet;

import java.util.Map;

public class SlotsResponse {
    private String type;
    private String error;
    private Map<?,?> slots;

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

    public Map<?, ?> getSlots() {
        return slots;
    }

    public void setSlots(Map<?, ?> slots) {
        this.slots = slots;
    }
}
