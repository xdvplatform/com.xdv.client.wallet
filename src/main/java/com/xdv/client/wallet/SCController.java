package com.xdv.client.wallet;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.TokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.async.DeferredResult;

import java.util.*;

import static org.springframework.web.bind.annotation.RequestMethod.*;

@RestController
public class SCController {

    private static final Logger log = LoggerFactory.getLogger(SCController.class);



    @RequestMapping(
            method = {GET},
            value = "/sc/get_slots")
    public DeferredResult<ResponseEntity<?>> getSlots() {
        DeferredResult<ResponseEntity<?>> deferredResult = new DeferredResult<ResponseEntity<?>>();
        ResponseEntity.BodyBuilder internalErr = ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON);

        try {
            ObjectMapper objectMapper = new ObjectMapper();

            PKCS11Service pkcs11Service = new PKCS11Service();
            pkcs11Service.initialize();
            Slot[] res = pkcs11Service.getSlots();
            Map<Long, String> mapper = new HashMap<>();
            Arrays.asList(res).forEach(c -> {
                try {
                    mapper.put(c.getSlotID(), objectMapper.writeValueAsString(c.getSlotInfo()));
                } catch (JsonProcessingException e) {
                    e.printStackTrace();
                } catch (TokenException e) {
                    e.printStackTrace();
                }
            });
            if (res != null) {
                deferredResult.setResult(ResponseEntity.ok(mapper));
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


    @RequestMapping(
            method = {POST},
            value = "/sc/sign/{tokenIndex}")
    public DeferredResult<ResponseEntity<?>> sign(
            @PathVariable()  int tokenIndex,
            @RequestBody()  SignPayload payload) {
        DeferredResult<ResponseEntity<?>> deferredResult = new DeferredResult<ResponseEntity<?>>();
        ResponseEntity.BodyBuilder internalErr = ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON);

        try {

            PKCS11Service pkcs11Service = new PKCS11Service();
            pkcs11Service.initialize();

            SignResponse response = pkcs11Service.signWithToken(
                    tokenIndex,
                    payload.getPin(),
                    Base64.getDecoder().decode(payload.getData())
            );
            if (response != null) {
                deferredResult.setResult(ResponseEntity.ok(response));
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


}
