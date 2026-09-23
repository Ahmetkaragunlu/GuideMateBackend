package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PurchaseSnapshotCodecTest {

    private final PurchaseSnapshotCodec codec = new PurchaseSnapshotCodec(
            new ObjectMapper().registerModule(new JavaTimeModule())
    );

    @Test
    void roundTripsImmutablePurchaseContract() {
        PurchaseSnapshot snapshot = snapshot();
        assertThat(codec.decode(codec.encode(snapshot))).isEqualTo(snapshot);
    }

    @Test
    void rejectsMalformedStoredSnapshot() {
        assertThatThrownBy(() -> codec.decode("{not-json"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Purchase snapshot could not be decoded");
    }

    private PurchaseSnapshot snapshot() {
        return new PurchaseSnapshot(
                1, UUID.randomUUID(), "Tur", "Açıklama", UUID.randomUUID(), 42L,
                "Test Rehber", UUID.randomUUID(), "TR", "istanbul", "İstanbul",
                "Europe/Istanbul", "culture", List.of("tr", "en"), UUID.randomUUID(),
                Instant.parse("2026-10-01T10:00:00Z"), 120, "Sultanahmet", 5_000,
                10_000, "USD", 2, "STANDARD", 1
        );
    }
}
