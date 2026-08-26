package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TourSchedulePolicyTest {

    private static final Long GUIDE_ID = 42L;
    private static final Instant NOW = Instant.parse("2026-08-27T10:00:00Z");
    private static final Instant STARTS_AT = Instant.parse("2026-08-27T12:00:00Z");
    private static final int DURATION_MINUTES = 90;
    private static final List<TourSessionStatus> MANAGEABLE_STATUSES = List.of(
            TourSessionStatus.OPEN_FOR_BOOKING,
            TourSessionStatus.CLOSED
    );
    private static final List<TourApprovalStatus> NON_BLOCKING_TOUR_STATUSES = List.of(
            TourApprovalStatus.REJECTED,
            TourApprovalStatus.ARCHIVED
    );

    private TourSessionRepository repository;
    private TourSchedulePolicy policy;

    @BeforeEach
    void setUp() {
        repository = mock(TourSessionRepository.class);
        policy = new TourSchedulePolicy(repository);
    }

    @Test
    void acceptsScheduleThatStartsWhenPreviousSessionEnds() {
        TourSession existing = sessionEndingAt(STARTS_AT);
        when(repository.findScheduleCandidates(
                GUIDE_ID,
                STARTS_AT.plusSeconds(DURATION_MINUTES * 60L),
                MANAGEABLE_STATUSES,
                NON_BLOCKING_TOUR_STATUSES
        )).thenReturn(List.of(existing));

        assertThatCode(() -> policy.validateNewSchedule(GUIDE_ID, STARTS_AT, DURATION_MINUTES, NOW))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsOverlappingSchedule() {
        TourSession existing = sessionEndingAt(STARTS_AT.plusSeconds(1));
        when(repository.findScheduleCandidates(
                GUIDE_ID,
                STARTS_AT.plusSeconds(DURATION_MINUTES * 60L),
                MANAGEABLE_STATUSES,
                NON_BLOCKING_TOUR_STATUSES
        )).thenReturn(List.of(existing));

        assertThatThrownBy(() -> policy.validateNewSchedule(GUIDE_ID, STARTS_AT, DURATION_MINUTES, NOW))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.SCHEDULE_CONFLICT));
    }

    @Test
    void excludesUpdatedSessionFromConflictQuery() {
        UUID sessionId = UUID.randomUUID();
        when(repository.findScheduleCandidates(
                GUIDE_ID,
                sessionId,
                STARTS_AT.plusSeconds(DURATION_MINUTES * 60L),
                MANAGEABLE_STATUSES,
                NON_BLOCKING_TOUR_STATUSES
        )).thenReturn(List.of());

        policy.validateUpdatedSchedule(GUIDE_ID, sessionId, STARTS_AT, DURATION_MINUTES, NOW);

        verify(repository).findScheduleCandidates(
                GUIDE_ID,
                sessionId,
                STARTS_AT.plusSeconds(DURATION_MINUTES * 60L),
                MANAGEABLE_STATUSES,
                NON_BLOCKING_TOUR_STATUSES
        );
    }

    @Test
    void rejectsScheduleAtOrBeforeCurrentTimeWithoutQueryingRepository() {
        assertThatThrownBy(() -> policy.validateNewSchedule(GUIDE_ID, NOW, DURATION_MINUTES, NOW))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.SESSION_ALREADY_STARTED));
    }

    private TourSession sessionEndingAt(Instant endsAt) {
        TourSession session = mock(TourSession.class);
        when(session.endsAt()).thenReturn(endsAt);
        return session;
    }
}
