package com.ahmetkaragunlu.guidematebackend.wallet;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.MonthlyGuideEarningResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class GuideEarningRepositoryIntegrationTest {

    @Autowired
    private GuideEarningService earningService;
    @Autowired
    private GuideEarningRepository earningRepository;
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
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private EntityManager entityManager;
    @Autowired
    private Clock clock;

    @Test
    void groupsMonthlyEarningsNewestFirstAndExcludesReversedRows() {
        User guide = createUser(RoleType.ROLE_GUIDE, "EarningGuide");
        User admin = createUser(RoleType.ROLE_ADMIN, "EarningAdmin");
        TourSession session = createSession(guide, admin);
        GuideEarning january = createEarning(session, 9_000, false, "JanuaryTourist");
        GuideEarning february = createEarning(session, 12_000, false, "FebruaryTourist");
        GuideEarning reversed = createEarning(session, 50_000, true, "ReversedTourist");
        setCreatedAt(january, Instant.parse("2026-01-15T12:00:00Z"));
        setCreatedAt(february, Instant.parse("2026-02-10T12:00:00Z"));
        setCreatedAt(reversed, Instant.parse("2026-02-20T12:00:00Z"));
        entityManager.clear();

        assertThat(earningService.getMonthlyEarnings(guide.getId(), 2026)).containsExactly(
                new MonthlyGuideEarningResponse(2026, 2, 12_000, "USD"),
                new MonthlyGuideEarningResponse(2026, 1, 9_000, "USD")
        );
    }

    private GuideEarning createEarning(
            TourSession session,
            long netMinor,
            boolean reversed,
            String touristName
    ) {
        User tourist = createUser(RoleType.ROLE_TOURIST, touristName);
        Reservation reservation = Reservation.hold(
                session,
                tourist,
                1,
                netMinor,
                netMinor,
                "USD",
                clock.instant().plus(10, ChronoUnit.MINUTES),
                "FULL_REFUND_48_HOURS",
                1,
                1,
                "{}",
                "earning-" + UUID.randomUUID()
        );
        reservation.confirm();
        reservation = reservationRepository.saveAndFlush(reservation);
        GuideEarning earning = new GuideEarning(
                reservation,
                netMinor,
                0,
                netMinor,
                "USD",
                session.endsAt()
        );
        if (reversed) {
            earning.reverse(clock.instant());
        }
        return earningRepository.saveAndFlush(earning);
    }

    private TourSession createSession(User guide, User admin) {
        MediaAsset cover = MediaAsset.pending(
                guide,
                MediaPurpose.TOUR_COVER,
                "earning-" + UUID.randomUUID() + ".png",
                "cover.png",
                "image/png",
                100
        );
        cover.markReady();
        cover = mediaAssetRepository.saveAndFlush(cover);
        Tour tour = Tour.submit(
                guide,
                new TourChangeSnapshot(
                        "Monthly earning tour",
                        "A sufficiently detailed description for a monthly earning query test.",
                        "TR",
                        "istanbul-earning",
                        "Istanbul",
                        "Europe/Istanbul",
                        "culture",
                        List.of("en"),
                        cover.getId()
                ),
                cover,
                clock.instant().minus(2, ChronoUnit.DAYS)
        );
        tour.approve(admin, clock.instant().minus(1, ChronoUnit.DAYS));
        tour = tourRepository.saveAndFlush(tour);
        return sessionRepository.saveAndFlush(TourSession.create(
                tour,
                "Earning meeting point",
                clock.instant().plus(1, ChronoUnit.DAYS),
                60,
                5_000,
                "USD",
                10,
                TourSessionStatus.OPEN_FOR_BOOKING
        ));
    }

    private User createUser(RoleType roleType, String firstName) {
        Role role = roleRepository.findByName(roleType.name()).orElseThrow();
        User user = new User();
        user.setFirstName(firstName);
        user.setLastName("Integration");
        user.setEmail(firstName.toLowerCase() + "-" + UUID.randomUUID() + "@example.com");
        user.setPassword("not-used");
        user.setRole(role);
        user.setRoleSelected(true);
        user.setAccountStatus(AccountStatus.ACTIVE);
        return userRepository.saveAndFlush(user);
    }

    private void setCreatedAt(GuideEarning earning, Instant createdAt) {
        jdbcTemplate.update(
                "UPDATE guide_earnings SET created_at = ? WHERE id = ?",
                Timestamp.from(createdAt),
                earning.getId()
        );
    }
}
