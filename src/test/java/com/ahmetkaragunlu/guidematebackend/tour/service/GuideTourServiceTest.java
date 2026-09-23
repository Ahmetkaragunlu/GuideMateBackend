package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.VersionPolicy;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaService;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.tour.config.TourProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuideTourServiceTest {

    @Mock private TourRepository tourRepository;
    @Mock private TourSessionRepository sessionRepository;
    @Mock private TourChangeRequestRepository changeRepository;
    @Mock private GuideProfileRepository profileRepository;
    @Mock private UserRepository userRepository;
    @Mock private MediaService mediaService;
    @Mock private TourContentFactory contentFactory;
    @Mock private TourChangeSnapshotCodec snapshotCodec;
    @Mock private TourSchedulePolicy schedulePolicy;
    @Mock private TourLocationPolicy locationPolicy;
    @Mock private VersionPolicy versionPolicy;
    @Mock private TourMapper mapper;
    @Mock private TourDetailQueryService detailQueryService;
    private GuideTourService service;

    @BeforeEach
    void setUp() {
        service = new GuideTourService(
                tourRepository,
                sessionRepository,
                changeRepository,
                profileRepository,
                userRepository,
                mediaService,
                contentFactory,
                snapshotCodec,
                schedulePolicy,
                locationPolicy,
                versionPolicy,
                mapper,
                detailQueryService,
                new TourProperties("USD"),
                Clock.systemUTC()
        );
    }

    @Test
    void rejectsArchivingPublishedApprovedTour() {
        UUID tourId = UUID.randomUUID();
        User guide = org.mockito.Mockito.mock(User.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        when(guide.getId()).thenReturn(42L);
        when(tourRepository.findOwnedByIdForUpdate(tourId, 42L)).thenReturn(Optional.of(tour));
        when(tour.getApprovalStatus()).thenReturn(TourApprovalStatus.APPROVED);

        assertThatThrownBy(() -> service.archiveTour(guide, tourId))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.TOUR_NOT_ARCHIVABLE));
        verify(tour, never()).archive();
    }
}
