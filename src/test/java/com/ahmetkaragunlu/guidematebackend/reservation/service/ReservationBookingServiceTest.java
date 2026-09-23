package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.reservation.config.ReservationProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
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
    @Mock private IdempotencyKeyPolicy idempotencyKeyPolicy;
    @Mock private CancellationPolicy cancellationPolicy;
    @Mock private NotificationPublisher notificationPublisher;
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
                new ReservationProperties(Duration.ofMinutes(15)),
                idempotencyKeyPolicy,
                cancellationPolicy,
                notificationPublisher,
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

    @Test
    void latePaymentRequiresRefundWhenCapacityIsNoLongerAvailable() {
        UUID reservationId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        TourSession session = bookableSession(sessionId);
        when(reservationRepository.findById(reservationId)).thenReturn(Optional.of(reservation));
        when(reservation.getSession()).thenReturn(session);
        when(sessionRepository.findByIdForUpdate(sessionId)).thenReturn(Optional.of(session));
        when(reservationRepository.findByIdForUpdate(reservationId)).thenReturn(Optional.of(reservation));
        when(reservation.getStatus()).thenReturn(ReservationStatus.PENDING_PAYMENT);
        when(reservation.isHoldExpired(NOW)).thenReturn(true);
        when(reservation.getParticipantCount()).thenReturn(2);
        when(reservation.getTourist()).thenReturn(org.mockito.Mockito.mock(User.class));
        when(capacityService.availableCapacity(session, 0)).thenReturn(1);

        ReservationFinalizationResult result = service.finalizeAfterPaymentVerification(reservationId);

        assertThat(result.refundRequired()).isTrue();
        verify(reservation).expire();
        verify(reservation, never()).confirmAfterVerifiedPayment();
        verify(notificationPublisher, never()).publish(org.mockito.ArgumentMatchers.any());
    }

    private TourSession bookableSession(UUID sessionId) {
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        User guide = org.mockito.Mockito.mock(User.class);
        when(session.getId()).thenReturn(sessionId);
        when(session.getTour()).thenReturn(tour);
        when(session.getStatus()).thenReturn(TourSessionStatus.OPEN_FOR_BOOKING);
        when(session.getStartsAt()).thenReturn(NOW.plusSeconds(3600));
        when(tour.getApprovalStatus()).thenReturn(TourApprovalStatus.APPROVED);
        when(tour.getGuide()).thenReturn(guide);
        when(guide.getAccountStatus()).thenReturn(AccountStatus.ACTIVE);
        when(guide.hasRole(RoleType.ROLE_GUIDE)).thenReturn(true);
        return session;
    }
}
