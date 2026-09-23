package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TourChangeSnapshotCodecTest {

    private final TourChangeSnapshotCodec codec = new TourChangeSnapshotCodec(new ObjectMapper());

    @Test
    void roundTripsProposedTourContent() {
        TourChangeSnapshot snapshot = new TourChangeSnapshot(
                "İstanbul Turu", "Açıklama", "TR", "istanbul", "İstanbul",
                "Europe/Istanbul", "culture", List.of("tr", "en"), UUID.randomUUID()
        );
        assertThat(codec.decode(codec.encode(snapshot))).isEqualTo(snapshot);
    }

    @Test
    void rejectsMalformedStoredSnapshot() {
        assertThatThrownBy(() -> codec.decode("[]"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Tour change snapshot could not be read");
    }
}
