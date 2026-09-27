package com.ahmetkaragunlu.guidematebackend.reservation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.support.persistence.PersistenceTestFixtures;
import com.ahmetkaragunlu.guidematebackend.support.persistence.PersistenceTestFixtures.ReservationFixture;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.UUID;

import static com.ahmetkaragunlu.guidematebackend.support.persistence.ConcurrentTestExecutor.run;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Import(PersistenceTestFixtures.class)
class ReservationConcurrencyIntegrationTest {

    @Autowired
    private PersistenceTestFixtures fixtures;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ReservationBookingService reservationBookingService;
    @Autowired
    private ReservationCapacityService reservationCapacityService;

    @Test
    void preventsConcurrentReservationsFromExceedingCapacity() throws Exception {
        ReservationFixture fixture = fixtures.createReservationFixture();

        List<ReservationAttempt> attempts = run(
                () -> createHold(fixture.firstTouristEmail(), fixture.sessionId(), "hold-a-" + UUID.randomUUID()),
                () -> createHold(fixture.secondTouristEmail(), fixture.sessionId(), "hold-b-" + UUID.randomUUID())
        );

        assertThat(attempts).filteredOn(attempt -> attempt.reservationId() != null).hasSize(1);
        assertThat(attempts).filteredOn(
                attempt -> attempt.errorCode() == ErrorCode.CAPACITY_NOT_AVAILABLE
        ).hasSize(1);
        assertThat(reservationCapacityService.occupiedCount(fixture.sessionId())).isEqualTo(1);
    }

    @Test
    void returnsSameReservationForConcurrentIdempotentRetry() throws Exception {
        ReservationFixture fixture = fixtures.createReservationFixture();
        String idempotencyKey = "same-hold-" + UUID.randomUUID();

        List<ReservationAttempt> attempts = run(
                () -> createHold(fixture.firstTouristEmail(), fixture.sessionId(), idempotencyKey),
                () -> createHold(fixture.firstTouristEmail(), fixture.sessionId(), idempotencyKey)
        );

        assertThat(attempts).allMatch(attempt -> attempt.errorCode() == null);
        assertThat(attempts).extracting(ReservationAttempt::reservationId).doesNotContainNull();
        assertThat(attempts.get(0).reservationId()).isEqualTo(attempts.get(1).reservationId());
    }

    private ReservationAttempt createHold(String touristEmail, UUID sessionId, String idempotencyKey) {
        try {
            User tourist = userRepository.findByEmailWithRole(touristEmail).orElseThrow();
            Reservation reservation = reservationBookingService.createHold(
                    tourist,
                    sessionId,
                    1,
                    idempotencyKey
            );
            return new ReservationAttempt(reservation.getId(), null);
        } catch (BusinessException exception) {
            return new ReservationAttempt(null, exception.getErrorCode());
        }
    }

    private record ReservationAttempt(UUID reservationId, ErrorCode errorCode) {
    }
}
