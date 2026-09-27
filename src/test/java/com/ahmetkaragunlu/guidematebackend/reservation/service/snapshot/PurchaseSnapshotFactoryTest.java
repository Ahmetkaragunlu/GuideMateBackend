package com.ahmetkaragunlu.guidematebackend.reservation.service.snapshot;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.ahmetkaragunlu.guidematebackend.reservation.service.lifecycle.CancellationPolicy;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PurchaseSnapshotFactoryTest {

    @Mock private GuideProfileRepository guideProfileRepository;
    @Mock private CancellationPolicy cancellationPolicy;
    @Mock private TourSession session;
    @Mock private Tour tour;
    @Mock private User guide;
    @Mock private MediaAsset coverMedia;
    private PurchaseSnapshotFactory factory;

    @BeforeEach
    void setUp() {
        factory = new PurchaseSnapshotFactory(guideProfileRepository, cancellationPolicy);
        when(session.getTour()).thenReturn(tour);
        when(tour.getGuide()).thenReturn(guide);
        when(guide.getId()).thenReturn(7L);
    }

    @Test
    void rejectsSnapshotWhenGuideProfileDoesNotExist() {
        when(guideProfileRepository.existsById(7L)).thenReturn(false);

        assertThatThrownBy(() -> factory.create(session, 2, 20_000L))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.GUIDE_PROFILE_NOT_FOUND));
    }

    @Test
    void createsVersionedSnapshotWhenGuideProfileExists() {
        UUID tourId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        UUID coverMediaId = UUID.randomUUID();
        Instant startsAt = Instant.parse("2026-10-01T10:00:00Z");
        when(guideProfileRepository.existsById(7L)).thenReturn(true);
        when(tour.getId()).thenReturn(tourId);
        when(tour.getTitle()).thenReturn("İstanbul Tarihi Yarımada Turu");
        when(tour.getDescription()).thenReturn("Tarihi yarımada yürüyüşü");
        when(tour.getCoverMedia()).thenReturn(coverMedia);
        when(coverMedia.getId()).thenReturn(coverMediaId);
        when(guide.displayName()).thenReturn("Ada Yılmaz");
        when(tour.getCountryCode()).thenReturn("TR");
        when(tour.getCityPlaceId()).thenReturn("istanbul");
        when(tour.getCityName()).thenReturn("İstanbul");
        when(tour.getTimeZoneId()).thenReturn("Europe/Istanbul");
        when(tour.getCategoryCode()).thenReturn("HISTORY");
        when(tour.getLanguageCodes()).thenReturn(Set.of("tr", "en"));
        when(session.getId()).thenReturn(sessionId);
        when(session.getStartsAt()).thenReturn(startsAt);
        when(session.getDurationMinutes()).thenReturn(180);
        when(session.getMeetingPoint()).thenReturn("Sultanahmet Meydanı");
        when(session.getPriceMinor()).thenReturn(10_000L);
        when(session.getCurrencyCode()).thenReturn("USD");
        when(cancellationPolicy.currentCode()).thenReturn("FULL_REFUND_48_HOURS");
        when(cancellationPolicy.currentVersion()).thenReturn(1);

        PurchaseSnapshot snapshot = factory.create(session, 2, 20_000L);

        assertThat(snapshot.snapshotVersion()).isEqualTo(PurchaseSnapshotFactory.CURRENT_SNAPSHOT_VERSION);
        assertThat(snapshot.tourId()).isEqualTo(tourId);
        assertThat(snapshot.sessionId()).isEqualTo(sessionId);
        assertThat(snapshot.totalPriceMinor()).isEqualTo(20_000L);
        assertThat(snapshot.languageCodes()).containsExactly("en", "tr");
    }
}
