package com.ahmetkaragunlu.guidematebackend.tour.service.content;

import com.ahmetkaragunlu.guidematebackend.tour.domain.change.TourChangeSnapshot;
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
