package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class TourSessionLifecycleService {

    private static final List<TourSessionStatus> COMPLETION_CANDIDATE_STATUSES = List.of(
            TourSessionStatus.OPEN_FOR_BOOKING,
            TourSessionStatus.CLOSED
    );

    private final TourSessionRepository tourSessionRepository;
    private final Clock clock;

    @Scheduled(fixedDelayString = "${tour.lifecycle-delay-ms:60000}")
    @Transactional
    public void completeFinishedSessions() {
        Instant now = clock.instant();
        tourSessionRepository.findByStatusInAndStartsAtBefore(COMPLETION_CANDIDATE_STATUSES, now)
                .stream()
                .filter(session -> !session.endsAt().isAfter(now))
                .forEach(TourSession::complete);
    }
}
