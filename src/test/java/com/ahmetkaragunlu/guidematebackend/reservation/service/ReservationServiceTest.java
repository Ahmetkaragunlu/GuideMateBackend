package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.common.validation.VersionPolicy;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentIntentService;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentRefundService;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationCancellationActor;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.CancelReservationRequest;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationCancellationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.mapper.ReservationMapper;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReservationServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-27T09:00:00Z");

    @Mock
    private ReservationRepository reservationRepository;
    @Mock
    private ReservationCapacityService reservationCapacityService;
    @Mock
    private ReviewQueryService reviewQueryService;
    @Mock
    private ReservationMapper reservationMapper;
    @Mock
    private CancellationPolicy cancellationPolicy;
    @Mock
    private PaymentRefundService paymentRefundService;
    @Mock
    private GuideEarningService guideEarningService;
    @Mock
    private ReservationBookingService reservationBookingService;
    @Mock
    private PaymentIntentService paymentIntentService;
    @Mock
    private NotificationPublisher notificationPublisher;

    private ReservationService service;

    @BeforeEach
    void setUp() {
        service = new ReservationService(
                reservationRepository,
                reservationCapacityService,
                reviewQueryService,
                reservationMapper,
                cancellationPolicy,
                Clock.fixed(NOW, ZoneOffset.UTC),
                new IdempotencyKeyPolicy(),
                new VersionPolicy(),
                paymentRefundService,
                guideEarningService,
                reservationBookingService,
                paymentIntentService,
                notificationPublisher
        );
    }

    @Test
    void returnsTripPageWithBatchedReviewAndCapacityProjections() {
        User tourist = tourist();
        UUID reservationId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        ReviewResponse review = org.mockito.Mockito.mock(ReviewResponse.class);
        ReviewAggregate aggregate = new ReviewAggregate(4.6, 12);
        ReservationResponse expected = org.mockito.Mockito.mock(ReservationResponse.class);
        PageRequest pageRequest = PageRequest.of(0, 20);

        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(sessionId);
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(tourId);
        when(reservationRepository.findUpcomingTrips(
                tourist.getId(),
                ReservationStatus.CONFIRMED,
                pageRequest
        )).thenReturn(new PageImpl<>(List.of(reservation), pageRequest, 1));
        when(reviewQueryService.reviewsByReservationIds(Set.of(reservationId)))
                .thenReturn(Map.of(reservationId, review));
        when(reviewQueryService.tourAggregates(Set.of(tourId)))
                .thenReturn(Map.of(tourId, aggregate));
        when(reservationCapacityService.occupiedCounts(Set.of(sessionId)))
                .thenReturn(Map.of(sessionId, 7));
        when(reservationMapper.toResponse(reservation, review, aggregate, 7)).thenReturn(expected);

        var result = service.getMyTrips(
                tourist,
                com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationTripStatus.UPCOMING,
                0,
                20
        );

        assertThat(result.content()).containsExactly(expected);
        verify(reviewQueryService).tourAggregates(Set.of(tourId));
        verify(reservationCapacityService).occupiedCounts(Set.of(sessionId));
        verify(reservationMapper).toResponse(reservation, review, aggregate, 7);
    }

    @Test
    void rejectsIdempotencyKeyPreviouslyUsedForAnotherReservation() {
        User tourist = tourist();
        UUID requestedReservationId = UUID.randomUUID();
        Reservation previous = org.mockito.Mockito.mock(Reservation.class);
        when(previous.getId()).thenReturn(UUID.randomUUID());
        when(reservationRepository.findByTourist_IdAndCancellationIdempotencyKey(42L, "same-key"))
                .thenReturn(Optional.of(previous));

        assertThatThrownBy(() -> service.cancel(
                tourist,
                requestedReservationId,
                " same-key ",
                new CancelReservationRequest(0L, null)
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.IDEMPOTENCY_CONFLICT));

        verify(reservationBookingService, never()).lockSessionForReservation(any());
    }

    @Test
    void rejectsStaleReservationVersionAfterLockingSession() {
        User tourist = tourist();
        UUID reservationId = UUID.randomUUID();
        Reservation reservation = lockedReservation(reservationId, 3L);

        assertThatThrownBy(() -> service.cancel(
                tourist,
                reservationId,
                "stale-version",
                new CancelReservationRequest(2L, null)
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CONCURRENT_UPDATE));

        verify(reservation, never()).cancel(any(), any(), any(), any(), any());
    }

    @Test
    void rejectsReservationThatIsAlreadyCompleted() {
        User tourist = tourist();
        UUID reservationId = UUID.randomUUID();
        Reservation reservation = lockedReservation(reservationId, 3L);
        when(reservation.getStatus()).thenReturn(ReservationStatus.COMPLETED);

        assertThatThrownBy(() -> service.cancel(
                tourist,
                reservationId,
                "completed",
                new CancelReservationRequest(3L, null)
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.RESERVATION_NOT_CANCELLABLE));

        verify(paymentIntentService, never()).cancelPendingForReservation(any());
    }

    @Test
    void cancelsWithoutRefundAndPublishesBothParticipantNotifications() {
        User tourist = tourist();
        UUID reservationId = UUID.randomUUID();
        Reservation reservation = lockedReservation(reservationId, 3L);
        when(reservation.getStatus()).thenReturn(ReservationStatus.CONFIRMED);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        User guide = org.mockito.Mockito.mock(User.class);
        when(reservation.getSession()).thenReturn(session);
        when(session.getId()).thenReturn(UUID.randomUUID());
        when(session.getStartsAt()).thenReturn(NOW.plusSeconds(3_600));
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(UUID.randomUUID());
        when(tour.getTitle()).thenReturn("Reservation tour");
        when(tour.getGuide()).thenReturn(guide);
        when(guide.getId()).thenReturn(7L);
        when(reservation.getTourist()).thenReturn(tourist);
        when(cancellationPolicy.touristEligibility(reservation, NOW)).thenReturn(RefundEligibility.NO_REFUND);
        when(reservation.getCancellationRefundEligibility()).thenReturn(RefundEligibility.NO_REFUND);
        when(reviewQueryService.reviewByReservationId(reservationId)).thenReturn(null);

        ReservationCancellationResponse result = service.cancel(
                tourist,
                reservationId,
                "no-refund",
                new CancelReservationRequest(3L, "  Plans changed  ")
        );

        assertThat(result.refundEligibility()).isEqualTo(RefundEligibility.NO_REFUND);
        assertThat(result.refundId()).isNull();
        verify(reservation).cancel(
                ReservationCancellationActor.TOURIST,
                "Plans changed",
                NOW,
                "no-refund",
                RefundEligibility.NO_REFUND
        );
        verify(paymentIntentService).cancelPendingForReservation(reservationId);
        verify(paymentRefundService, never()).requestFullRefundForReservation(any(), any(), any());
        verify(guideEarningService, never()).reverse(any());
        ArgumentCaptor<NotificationCommand> notificationCaptor =
                ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher, org.mockito.Mockito.times(2)).publish(notificationCaptor.capture());
        assertThat(notificationCaptor.getAllValues())
                .extracting(NotificationCommand::type)
                .containsOnly(NotificationType.RESERVATION_CANCELLED);
        assertThat(notificationCaptor.getAllValues())
                .extracting(NotificationCommand::recipientId)
                .containsExactlyInAnyOrder(tourist.getId(), guide.getId());
    }

    private User tourist() {
        User tourist = org.mockito.Mockito.mock(User.class);
        when(tourist.getId()).thenReturn(42L);
        return tourist;
    }

    private Reservation lockedReservation(UUID reservationId, long version) {
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        when(reservationRepository.findByTourist_IdAndCancellationIdempotencyKey(
                org.mockito.ArgumentMatchers.eq(42L),
                org.mockito.ArgumentMatchers.anyString()
        ))
                .thenReturn(Optional.empty());
        when(reservationRepository.findOwnedDetails(reservationId, 42L)).thenReturn(Optional.of(reservation));
        when(reservationRepository.findOwnedByIdForUpdate(reservationId, 42L))
                .thenReturn(Optional.of(reservation));
        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getVersion()).thenReturn(version);
        return reservation;
    }
}
