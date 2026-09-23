package com.ahmetkaragunlu.guidematebackend.reservation.mapper;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.service.PurchaseSnapshotCodec;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReservationMapperTest {

    @Mock
    private PurchaseSnapshotCodec snapshotCodec;
    @Mock
    private MediaReferenceMapper mediaReferenceMapper;
    @Mock
    private Reservation reservation;
    @Mock
    private TourSession session;

    private ReservationMapper mapper;

    @BeforeEach
    void setUp() {
        mapper = new ReservationMapper(snapshotCodec, mediaReferenceMapper);
        when(reservation.getPurchaseSnapshot()).thenReturn("snapshot");
        when(reservation.getSession()).thenReturn(session);
    }

    @Test
    void mapsSnapshotAvatarAndCoverThroughSharedMediaMapper() {
        UUID avatarId = UUID.randomUUID();
        UUID coverId = UUID.randomUUID();
        PurchaseSnapshot snapshot = snapshot(avatarId, coverId);
        MediaReferenceResponse avatar = new MediaReferenceResponse(avatarId, "/avatar");
        MediaReferenceResponse cover = new MediaReferenceResponse(coverId, "/cover");
        when(snapshotCodec.decode("snapshot")).thenReturn(snapshot);
        when(mediaReferenceMapper.fromId(avatarId)).thenReturn(avatar);
        when(mediaReferenceMapper.fromId(coverId)).thenReturn(cover);

        ReservationResponse response = mapper.toResponse(reservation, null, ReviewAggregate.EMPTY, 0);

        assertThat(response.snapshot().guide().avatar()).isEqualTo(avatar);
        assertThat(response.snapshot().cover()).isEqualTo(cover);
        verify(mediaReferenceMapper).fromId(avatarId);
        verify(mediaReferenceMapper).fromId(coverId);
    }

    @Test
    void keepsOptionalGuideAvatarNullWhileMappingRequiredCover() {
        UUID coverId = UUID.randomUUID();
        PurchaseSnapshot snapshot = snapshot(null, coverId);
        MediaReferenceResponse cover = new MediaReferenceResponse(coverId, "/cover");
        when(snapshotCodec.decode("snapshot")).thenReturn(snapshot);
        when(mediaReferenceMapper.fromId(null)).thenReturn(null);
        when(mediaReferenceMapper.fromId(coverId)).thenReturn(cover);

        ReservationResponse response = mapper.toResponse(reservation, null, ReviewAggregate.EMPTY, 0);

        assertThat(response.snapshot().guide().avatar()).isNull();
        assertThat(response.snapshot().cover()).isEqualTo(cover);
        verify(mediaReferenceMapper).fromId(null);
        verify(mediaReferenceMapper).fromId(coverId);
    }

    private PurchaseSnapshot snapshot(UUID avatarId, UUID coverId) {
        return new PurchaseSnapshot(
                1,
                UUID.randomUUID(),
                "Tarihi İstanbul",
                "Açıklama",
                coverId,
                42L,
                "Ayşe Yılmaz",
                avatarId,
                "TR",
                "ChIJiX9L-t9OyhQRv3uPRv5UZ4o",
                "İstanbul",
                "Europe/Istanbul",
                "culture",
                List.of("tr", "en"),
                UUID.randomUUID(),
                Instant.parse("2027-05-24T06:00:00Z"),
                180,
                "Sultanahmet Meydanı",
                15_000,
                30_000,
                "USD",
                2,
                "STANDARD",
                1
        );
    }
}
