package com.ahmetkaragunlu.guidematebackend.review.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import com.ahmetkaragunlu.guidematebackend.review.dto.CreateReviewRequest;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.mapper.ReviewMapper;
import com.ahmetkaragunlu.guidematebackend.review.repository.ReviewRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReviewServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-27T09:00:00Z");

    @Mock
    private ReservationRepository reservationRepository;
    @Mock
    private ReviewRepository reviewRepository;
    @Mock
    private ReviewMapper reviewMapper;
    @Mock
    private NotificationPublisher notificationPublisher;

    private ReviewService service;

    @BeforeEach
    void setUp() {
        service = new ReviewService(
                reservationRepository,
                reviewRepository,
                reviewMapper,
                notificationPublisher,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void submitsTrimmedCommentAndPublishesGuideNotification() {
        ReviewFixture fixture = completedReservation(true);
        ReviewResponse expected = new ReviewResponse(UUID.randomUUID(), 5, "Excellent tour", NOW);
        when(reviewRepository.existsByReservation_Id(fixture.reservationId())).thenReturn(false);
        when(reviewRepository.saveAndFlush(any(Review.class))).thenAnswer(invocation -> {
            Review review = invocation.getArgument(0);
            ReflectionTestUtils.setField(review, "id", expected.reviewId());
            return review;
        });
        when(reviewMapper.toResponse(any(Review.class))).thenReturn(expected);

        ReviewResponse result = service.submit(
                fixture.tourist(),
                fixture.reservationId(),
                new CreateReviewRequest(5, "  Excellent tour  ")
        );

        assertThat(result).isEqualTo(expected);
        ArgumentCaptor<Review> reviewCaptor = ArgumentCaptor.forClass(Review.class);
        verify(reviewRepository).saveAndFlush(reviewCaptor.capture());
        assertThat(reviewCaptor.getValue().getComment()).isEqualTo("Excellent tour");
        ArgumentCaptor<NotificationCommand> notificationCaptor =
                ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher).publish(notificationCaptor.capture());
        assertThat(notificationCaptor.getValue().type()).isEqualTo(NotificationType.COMMENT_RECEIVED);
        assertThat(notificationCaptor.getValue().recipientId()).isEqualTo(fixture.guideId());
        assertThat(notificationCaptor.getValue().actorId()).isEqualTo(fixture.tourist().getId());
        assertThat(notificationCaptor.getValue().payload())
                .containsEntry("reviewId", expected.reviewId().toString())
                .containsEntry("tourTitle", "Review tour")
                .containsEntry("rating", (short) 5);
    }

    @Test
    void rejectsReviewUntilReservationAndSessionAreCompleted() {
        UUID reservationId = UUID.randomUUID();
        User tourist = org.mockito.Mockito.mock(User.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        when(tourist.getId()).thenReturn(42L);
        when(reservationRepository.findOwnedByIdForUpdate(reservationId, 42L))
                .thenReturn(Optional.of(reservation));
        when(reservation.getStatus()).thenReturn(ReservationStatus.CONFIRMED);

        assertThatThrownBy(() -> service.submit(
                tourist,
                reservationId,
                new CreateReviewRequest(4, null)
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.REVIEW_NOT_ALLOWED));

        verify(reviewRepository, never()).saveAndFlush(any());
        verify(notificationPublisher, never()).publish(any());
    }

    @Test
    void mapsConcurrentDuplicateInsertToStableReviewError() {
        ReviewFixture fixture = completedReservation(false);
        when(reviewRepository.existsByReservation_Id(fixture.reservationId())).thenReturn(false);
        when(reviewRepository.saveAndFlush(any(Review.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate"));

        assertThatThrownBy(() -> service.submit(
                fixture.tourist(),
                fixture.reservationId(),
                new CreateReviewRequest(4, null)
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.REVIEW_ALREADY_EXISTS));

        verify(notificationPublisher, never()).publish(any());
    }

    private ReviewFixture completedReservation(boolean notificationGraphRequired) {
        UUID reservationId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        long guideId = 7L;
        User tourist = org.mockito.Mockito.mock(User.class);
        User guide = org.mockito.Mockito.mock(User.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);

        when(tourist.getId()).thenReturn(42L);
        when(reservationRepository.findOwnedByIdForUpdate(reservationId, 42L))
                .thenReturn(Optional.of(reservation));
        when(reservation.getStatus()).thenReturn(ReservationStatus.COMPLETED);
        when(reservation.getSession()).thenReturn(session);
        when(session.endsAt()).thenReturn(NOW.minusSeconds(1));
        if (notificationGraphRequired) {
            when(guide.getId()).thenReturn(guideId);
            when(session.getId()).thenReturn(sessionId);
            when(session.getTour()).thenReturn(tour);
            when(tour.getId()).thenReturn(tourId);
            when(tour.getTitle()).thenReturn("Review tour");
            when(tour.getGuide()).thenReturn(guide);
            when(reservation.getId()).thenReturn(reservationId);
            when(reservation.getTourist()).thenReturn(tourist);
        }
        return new ReviewFixture(reservationId, tourist, guideId);
    }

    private record ReviewFixture(UUID reservationId, User tourist, long guideId) {
    }
}
