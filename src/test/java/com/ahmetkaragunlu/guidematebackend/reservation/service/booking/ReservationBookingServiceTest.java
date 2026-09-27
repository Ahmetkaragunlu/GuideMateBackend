package com.ahmetkaragunlu.guidematebackend.reservation.service.booking;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.reservation.config.ReservationProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.lifecycle.CancellationPolicy;
import com.ahmetkaragunlu.guidematebackend.reservation.service.snapshot.PurchaseSnapshotCodec;
import com.ahmetkaragunlu.guidematebackend.reservation.service.snapshot.PurchaseSnapshotFactory;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReservationBookingServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @Mock private ReservationRepository reservationRepository;
    @Mock private TourSessionRepository sessionRepository;
    @Mock private UserRepository userRepository;
    @Mock private ReservationCapacityService capacityService;
    @Mock private PurchaseSnapshotFactory snapshotFactory;
    @Mock private PurchaseSnapshotCodec snapshotCodec;
    @Mock private ReservationBookabilityPolicy bookabilityPolicy;
    @Mock private IdempotencyKeyPolicy idempotencyKeyPolicy;
    @Mock private CancellationPolicy cancellationPolicy;
    private ReservationBookingService service;

    @BeforeEach
    void setUp() {
        service = new ReservationBookingService(
                reservationRepository,
                sessionRepository,
                userRepository,
                capacityService,
                snapshotFactory,
                snapshotCodec,
                bookabilityPolicy,
                new ReservationProperties(Duration.ofMinutes(15)),
                idempotencyKeyPolicy,
                cancellationPolicy,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void rejectsReusedIdempotencyKeyForDifferentBooking() {
        User tourist = org.mockito.Mockito.mock(User.class);
        Reservation previous = org.mockito.Mockito.mock(Reservation.class);
        TourSession previousSession = org.mockito.Mockito.mock(TourSession.class);
        UUID previousSessionId = UUID.randomUUID();
        UUID requestedSessionId = UUID.randomUUID();
        when(tourist.hasRole(RoleType.ROLE_TOURIST)).thenReturn(true);
        when(tourist.getId()).thenReturn(42L);
        when(idempotencyKeyPolicy.normalize("same-key")).thenReturn("same-key");
        when(reservationRepository.findByTourist_IdAndIdempotencyKey(42L, "same-key"))
                .thenReturn(Optional.of(previous));
        when(previous.getSession()).thenReturn(previousSession);
        when(previousSession.getId()).thenReturn(previousSessionId);

        assertThatThrownBy(() -> service.createHold(tourist, requestedSessionId, 2, "same-key"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.IDEMPOTENCY_CONFLICT));
        verify(sessionRepository, never()).findByIdForUpdate(requestedSessionId);
    }

}
