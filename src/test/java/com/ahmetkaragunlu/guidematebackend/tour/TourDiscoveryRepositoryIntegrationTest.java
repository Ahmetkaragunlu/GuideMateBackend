package com.ahmetkaragunlu.guidematebackend.tour;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSearchSort;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourDiscoveryRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSearchCriteria;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class TourDiscoveryRepositoryIntegrationTest {

    @Autowired
    private TourDiscoveryRepository discoveryRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private MediaAssetRepository mediaAssetRepository;
    @Autowired
    private TourRepository tourRepository;
    @Autowired
    private TourSessionRepository sessionRepository;
    @Autowired
    private ReservationRepository reservationRepository;
    @Autowired
    private Clock clock;

    @Test
    void appliesGuideFilterAndCountsOnlyLiveCapacityHolds() {
        Instant now = clock.instant();
        User admin = createUser(RoleType.ROLE_ADMIN, AccountStatus.ACTIVE, "DiscoveryAdmin");
        User selectedGuide = createUser(RoleType.ROLE_GUIDE, AccountStatus.ACTIVE, "SelectedGuide");
        User otherGuide = createUser(RoleType.ROLE_GUIDE, AccountStatus.ACTIVE, "OtherGuide");
        User tourist = createUser(RoleType.ROLE_TOURIST, AccountStatus.ACTIVE, "DiscoveryTourist");
        Tour selectedTour = createApprovedTour(selectedGuide, admin, "Selected tour", now);
        Tour otherTour = createApprovedTour(otherGuide, admin, "Other tour", now);
        TourSession available = createSession(selectedTour, now.plus(1, ChronoUnit.DAYS), 2);
        TourSession full = createSession(selectedTour, now.plus(2, ChronoUnit.DAYS), 1);
        TourSession expiredHold = createSession(selectedTour, now.plus(3, ChronoUnit.DAYS), 1);
        createSession(otherTour, now.plus(4, ChronoUnit.DAYS), 5);
        createReservation(full, tourist, now.plus(10, ChronoUnit.MINUTES), "full", true);
        createReservation(expiredHold, tourist, now.minus(1, ChronoUnit.MINUTES), "expired", false);

        TourSearchCriteria criteria = new TourSearchCriteria(
                null,
                selectedGuide.getId(),
                null,
                null,
                null,
                Set.of(),
                null,
                null,
                null,
                0,
                20,
                TourSearchSort.STARTS_AT_ASC,
                now
        );

        assertThat(discoveryRepository.search(criteria).getContent())
                .extracting(TourSession::getId)
                .containsExactly(available.getId(), expiredHold.getId());
    }

    private User createUser(RoleType roleType, AccountStatus status, String firstName) {
        Role role = roleRepository.findByName(roleType.name()).orElseThrow();
        User user = new User();
        user.setFirstName(firstName);
        user.setLastName("Integration");
        user.setEmail(firstName.toLowerCase() + "-" + UUID.randomUUID() + "@example.com");
        user.setPassword("not-used");
        user.setRole(role);
        user.setRoleSelected(true);
        user.setAccountStatus(status);
        return userRepository.saveAndFlush(user);
    }

    private Tour createApprovedTour(User guide, User admin, String title, Instant now) {
        MediaAsset cover = MediaAsset.pending(
                guide,
                MediaPurpose.TOUR_COVER,
                "discovery-" + UUID.randomUUID() + ".png",
                "cover.png",
                "image/png",
                100
        );
        cover.markReady();
        cover = mediaAssetRepository.saveAndFlush(cover);
        Tour tour = Tour.submit(
                guide,
                new TourChangeSnapshot(
                        title,
                        "A sufficiently detailed description for a discovery repository test.",
                        "TR",
                        "istanbul-discovery",
                        "Istanbul",
                        "Europe/Istanbul",
                        "culture",
                        List.of("en"),
                        cover.getId()
                ),
                cover,
                now.minus(1, ChronoUnit.DAYS)
        );
        tour.approve(admin, now.minus(12, ChronoUnit.HOURS));
        return tourRepository.saveAndFlush(tour);
    }

    private TourSession createSession(Tour tour, Instant startsAt, int capacity) {
        return sessionRepository.saveAndFlush(TourSession.create(
                tour,
                "Discovery meeting point",
                startsAt,
                60,
                5_000,
                "USD",
                capacity,
                TourSessionStatus.OPEN_FOR_BOOKING
        ));
    }

    private void createReservation(
            TourSession session,
            User tourist,
            Instant holdExpiresAt,
            String idempotencyKey,
            boolean confirmed
    ) {
        Reservation reservation = Reservation.hold(
                session,
                tourist,
                1,
                session.getPriceMinor(),
                session.getPriceMinor(),
                "USD",
                holdExpiresAt,
                "FULL_REFUND_48_HOURS",
                1,
                1,
                "{}",
                idempotencyKey + "-" + UUID.randomUUID()
        );
        if (confirmed) {
            reservation.confirm();
        }
        reservationRepository.saveAndFlush(reservation);
    }
}
