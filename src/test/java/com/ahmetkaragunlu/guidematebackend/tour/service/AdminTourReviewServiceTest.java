package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewType;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminTourReviewServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-27T09:00:00Z");

    @Mock
    private TourRepository tourRepository;
    @Mock
    private TourSessionRepository tourSessionRepository;
    @Mock
    private TourChangeRequestRepository changeRequestRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private MediaService mediaService;
    @Mock
    private TourContentFactory tourContentFactory;
    @Mock
    private TourChangeSnapshotCodec snapshotCodec;
    @Mock
    private TourLocationPolicy locationPolicy;
    @Mock
    private TourDetailQueryService tourDetailQueryService;
    @Mock
    private NotificationPublisher notificationPublisher;

    private AdminTourReviewService service;

    @BeforeEach
    void setUp() {
        service = new AdminTourReviewService(
                tourRepository,
                tourSessionRepository,
                changeRequestRepository,
                userRepository,
                mediaService,
                tourContentFactory,
                snapshotCodec,
                locationPolicy,
                tourDetailQueryService,
                notificationPublisher,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void approvesNewTourAndOpensOnlyFutureManageableSessions() {
        UUID reviewId = UUID.randomUUID();
        User admin = admin();
        User guide = guide();
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        TourSession future = org.mockito.Mockito.mock(TourSession.class);
        TourSession finished = org.mockito.Mockito.mock(TourSession.class);
        TourDetailResponse detail = org.mockito.Mockito.mock(TourDetailResponse.class);
        when(changeRequestRepository.findByIdForUpdate(reviewId)).thenReturn(Optional.empty());
        when(tourRepository.findByIdForUpdate(reviewId)).thenReturn(Optional.of(tour));
        when(tour.getApprovalStatus())
                .thenReturn(TourApprovalStatus.PENDING_REVIEW, TourApprovalStatus.APPROVED);
        when(tour.getId()).thenReturn(reviewId);
        when(tour.getGuide()).thenReturn(guide);
        when(tour.getTitle()).thenReturn("Approved tour");
        when(tourSessionRepository.findAllByTour_IdOrderByStartsAtAsc(reviewId))
                .thenReturn(List.of(future, finished));
        when(future.getStatus()).thenReturn(TourSessionStatus.CLOSED);
        when(future.endsAt()).thenReturn(NOW.plusSeconds(7_200));
        when(future.getStartsAt()).thenReturn(NOW.plusSeconds(3_600));
        when(finished.getStatus()).thenReturn(TourSessionStatus.CLOSED);
        when(finished.endsAt()).thenReturn(NOW.minusSeconds(1));
        when(tourDetailQueryService.getDetail(tour)).thenReturn(detail);

        var response = service.approve(admin, reviewId);

        assertThat(response.type()).isEqualTo(AdminTourReviewType.NEW_TOUR);
        assertThat(response.status()).isEqualTo(TourApprovalStatus.APPROVED.name());
        assertThat(response.tour()).isSameAs(detail);
        verify(tour).approve(admin, NOW);
        verify(future).open();
        verify(finished).complete();
        ArgumentCaptor<NotificationCommand> notificationCaptor =
                ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher).publish(notificationCaptor.capture());
        assertThat(notificationCaptor.getValue().type()).isEqualTo(NotificationType.TOUR_APPROVED);
        assertThat(notificationCaptor.getValue().recipientId()).isEqualTo(guide.getId());
    }

    @Test
    void rejectsChangeApprovalWhenTourVersionMovedForward() {
        UUID reviewId = UUID.randomUUID();
        User admin = admin();
        TourChangeRequest changeRequest = org.mockito.Mockito.mock(TourChangeRequest.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        when(changeRequestRepository.findByIdForUpdate(reviewId))
                .thenReturn(Optional.of(changeRequest));
        when(changeRequest.getStatus()).thenReturn(TourChangeRequestStatus.PENDING);
        when(changeRequest.getTour()).thenReturn(tour);
        when(changeRequest.getBaseVersion()).thenReturn(4L);
        when(tour.getId()).thenReturn(UUID.randomUUID());
        when(tour.getApprovalStatus()).thenReturn(TourApprovalStatus.APPROVED);
        when(tour.getVersion()).thenReturn(5L);
        when(tourRepository.findByIdForUpdate(tour.getId())).thenReturn(Optional.of(tour));

        assertThatThrownBy(() -> service.approve(admin, reviewId))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CONCURRENT_UPDATE));

        verify(changeRequest, never()).approve(admin, NOW);
        verify(notificationPublisher, never()).publish(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void rejectsNewTourAndClosesManageableSessions() {
        UUID reviewId = UUID.randomUUID();
        User admin = admin();
        User guide = guide();
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        when(changeRequestRepository.findByIdForUpdate(reviewId)).thenReturn(Optional.empty());
        when(tourRepository.findByIdForUpdate(reviewId)).thenReturn(Optional.of(tour));
        when(tour.getApprovalStatus())
                .thenReturn(TourApprovalStatus.PENDING_REVIEW, TourApprovalStatus.REJECTED);
        when(tour.getId()).thenReturn(reviewId);
        when(tour.getGuide()).thenReturn(guide);
        when(tour.getTitle()).thenReturn("Rejected tour");
        when(tourSessionRepository.findAllByTour_IdOrderByStartsAtAsc(reviewId))
                .thenReturn(List.of(session));
        when(session.getStatus()).thenReturn(TourSessionStatus.OPEN_FOR_BOOKING);

        var response = service.reject(admin, reviewId, "Insufficient detail");

        assertThat(response.status()).isEqualTo(TourApprovalStatus.REJECTED.name());
        verify(tour).reject(admin, "Insufficient detail", NOW);
        verify(session).close();
        ArgumentCaptor<NotificationCommand> notificationCaptor =
                ArgumentCaptor.forClass(NotificationCommand.class);
        verify(notificationPublisher).publish(notificationCaptor.capture());
        assertThat(notificationCaptor.getValue().type()).isEqualTo(NotificationType.TOUR_REJECTED);
        assertThat(notificationCaptor.getValue().payload())
                .containsEntry("rejectionReason", "Insufficient detail");
    }

    private User admin() {
        User admin = org.mockito.Mockito.mock(User.class);
        when(admin.getId()).thenReturn(1L);
        when(userRepository.getReferenceById(1L)).thenReturn(admin);
        return admin;
    }

    private User guide() {
        User guide = org.mockito.Mockito.mock(User.class);
        when(guide.getId()).thenReturn(7L);
        return guide;
    }
}
