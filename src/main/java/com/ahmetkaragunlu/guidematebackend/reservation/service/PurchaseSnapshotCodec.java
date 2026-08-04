package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PurchaseSnapshotCodec {

    private final ObjectMapper objectMapper;

    public String encode(PurchaseSnapshot snapshot) {
        try {
            return objectMapper.writeValueAsString(snapshot);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Purchase snapshot could not be encoded", exception);
        }
    }

    public PurchaseSnapshot decode(String snapshot) {
        try {
            return objectMapper.readValue(snapshot, PurchaseSnapshot.class);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Purchase snapshot could not be decoded", exception);
        }
    }
}
