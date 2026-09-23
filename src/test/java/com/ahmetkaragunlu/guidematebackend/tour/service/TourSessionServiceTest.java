package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.common.validation.VersionPolicy;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationLifecycleService;
import com.ahmetkaragunlu.guidematebackend.tour.config.TourProperties;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.UpdateTourSessionRequest;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
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
class TourSessionServiceTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @Mock private TourRepository tourRepository;
    @Mock private TourSessionRepository sessionRepository;
    @Mock private TourSchedulePolicy schedulePolicy;
    @Mock private TourMapper tourMapper;
    @Mock private ReservationCapacityService capacityService;
    @Mock private ReservationLifecycleService lifecycleService;
    @Mock private IdempotencyKeyPolicy idempotencyKeyPolicy;
    @Mock private VersionPolicy versionPolicy;
    private TourSessionService service;

    @BeforeEach
    void setUp() {
        service = new TourSessionService(
                tourRepository,
                sessionRepository,
                schedulePolicy,
                tourMapper,
                new TourProperties("USD"),
                capacityService,
                lifecycleService,
                idempotencyKeyPolicy,
                versionPolicy,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void rejectsCapacityBelowAlreadyBookedParticipants() {
        UUID sessionId = UUID.randomUUID();
        User guide = org.mockito.Mockito.mock(User.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        UpdateTourSessionRequest request = org.mockito.Mockito.mock(UpdateTourSessionRequest.class);
        when(guide.getId()).thenReturn(42L);
        when(sessionRepository.findOwnedByIdForUpdate(sessionId, 42L)).thenReturn(Optional.of(session));
        when(session.getStatus()).thenReturn(TourSessionStatus.OPEN_FOR_BOOKING);
        when(session.getStartsAt()).thenReturn(NOW.plusSeconds(3600));
        when(request.capacity()).thenReturn(3);
        when(capacityService.occupiedCount(sessionId)).thenReturn(4);

        assertThatThrownBy(() -> service.updateSession(guide, sessionId, request))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.CAPACITY_BELOW_BOOKED_COUNT));
        verify(session, never()).updateSchedule(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.anyInt(),
                org.mockito.ArgumentMatchers.anyLong(),
                org.mockito.ArgumentMatchers.anyInt()
        );
    }
}
