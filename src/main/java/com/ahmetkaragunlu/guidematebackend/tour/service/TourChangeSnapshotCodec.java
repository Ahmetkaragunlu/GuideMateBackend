package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TourChangeSnapshotCodec {

    private final ObjectMapper objectMapper;

    public String encode(TourChangeSnapshot snapshot) {
        try {
            return objectMapper.writeValueAsString(snapshot);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Tour change snapshot could not be serialized", exception);
        }
    }

    public TourChangeSnapshot decode(String snapshot) {
        try {
            return objectMapper.readValue(snapshot, TourChangeSnapshot.class);
        } catch (JsonProcessingException exception) {
            throw new IllegalStateException("Tour change snapshot could not be read", exception);
        }
    }
}
