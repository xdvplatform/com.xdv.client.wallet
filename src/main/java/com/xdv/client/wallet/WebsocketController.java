package com.xdv.client.wallet;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;
import org.bouncycastle.cms.CMSException;
import org.springframework.messaging.Message;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.web3j.crypto.Sign;
import org.web3j.utils.Convert;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Controller
public class WebsocketController {
    @MessageMapping("/ping")
    @SendTo("/xdv/messages")
    public String ping() {
        return "PONG";
    }

    @MessageMapping("/get_slots")
    @SendTo("/xdv/messages")
    public SlotsResponse getSlots(Message message) throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        PKCS11Service pkcs11Service = new PKCS11Service();
        pkcs11Service.initialize();
        Slot[] res = pkcs11Service.getSlots();
        Map<Long, String> mapper = new HashMap<>();
        SlotsResponse slotsResponse = new SlotsResponse();
        slotsResponse.setType("slots");
        Arrays.asList(res).forEach(c -> {
            try {
                mapper.put(c.getSlotID(), objectMapper.writeValueAsString(c.getSlotInfo()));
                slotsResponse.setSlots(mapper);
            } catch (JsonProcessingException e) {
                slotsResponse.setError(e.getMessage());
                e.printStackTrace();
            } catch (TokenException e) {
                slotsResponse.setError(e.getMessage());
                e.printStackTrace();
            }
        });
        return slotsResponse;
    }


    @MessageMapping("/get_certificates")
    @SendTo("/xdv/certificates")
    public SignResponse getCerts(Message message) {
        SignResponse response = new SignResponse();
        PKCS11Service pkcs11Service = new PKCS11Service();
        response.setType("certificates");
        try {
            pkcs11Service.initialize();
            Object p = message.getPayload();
            ObjectMapper mapper  = new ObjectMapper();
            SignPayload payload;
            payload = mapper.readValue((byte[]) p, SignPayload.class);

            response = pkcs11Service.getPublicKey(
                    payload.getTokenIndex(),
                    payload.getPin());
            response.setType("certificates");
        } catch (TokenException | NoSuchAlgorithmException | CertificateException | CMSException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();
            response.setError(e.getMessage());
        } catch (IOException e) {
            response.setError(e.getMessage());
        }
        return response;
    }

    @MessageMapping("/sign")
    @SendTo("/xdv/signed")
    public SignResponse sign(Message message) throws ParseException, JOSEException {
        SignResponse response = new SignResponse();
        PKCS11Service pkcs11Service = new PKCS11Service();
        response.setType("signing");
        try {
            pkcs11Service.initialize();
            Object p = message.getPayload();
            ObjectMapper mapper  = new ObjectMapper();
            SignPayload payload;
            payload = mapper.readValue((byte[]) p, SignPayload.class);

            response = pkcs11Service.signWithToken(
                    payload.getTokenIndex(),
                    payload.getPin(),
                    payload.getData().getBytes());
            response.setType("signing");
        } catch (TokenException | NoSuchAlgorithmException | CertificateException | CMSException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();
            response.setError(e.getMessage());
        } catch (IOException e) {
            response.setError(e.getMessage());
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return response;
    }
}
