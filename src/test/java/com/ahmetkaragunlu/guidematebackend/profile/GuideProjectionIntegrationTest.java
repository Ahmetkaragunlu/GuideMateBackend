package com.ahmetkaragunlu.guidematebackend.profile;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideSearchItemResponse;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.profile.service.GuideDiscoveryService;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import com.ahmetkaragunlu.guidematebackend.review.repository.ReviewRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideDashboardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.tour.service.GuideDashboardService;
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
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class GuideProjectionIntegrationTest {

    @Autowired
    private GuideDiscoveryService guideDiscoveryService;
    @Autowired
    private GuideDashboardService guideDashboardService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private GuideProfileRepository guideProfileRepository;
    @Autowired
    private MediaAssetRepository mediaAssetRepository;
    @Autowired
    private TourRepository tourRepository;
    @Autowired
    private TourSessionRepository tourSessionRepository;
    @Autowired
    private ReservationRepository reservationRepository;
    @Autowired
    private ReviewRepository reviewRepository;
    @Autowired
    private Clock clock;

    @Test
    void searchReturnsOnlyActiveGuidesAndPreservesDatabasePagination() {
        String searchToken = "Search" + UUID.randomUUID().toString().replace("-", "");
        createProfile(searchToken + "Alpha", RoleType.ROLE_GUIDE, AccountStatus.ACTIVE);
        createProfile(searchToken + "Beta", RoleType.ROLE_GUIDE, AccountStatus.ACTIVE);
        createProfile(searchToken + "Disabled", RoleType.ROLE_GUIDE, AccountStatus.DISABLED);
        createProfile(searchToken + "Tourist", RoleType.ROLE_TOURIST, AccountStatus.ACTIVE);

        PageResponse<GuideSearchItemResponse> firstPage = guideDiscoveryService.search(
                searchToken,
                0,
                1
        );

        assertThat(firstPage.content()).hasSize(1);
        assertThat(firstPage.totalElements()).isEqualTo(2);
        assertThat(firstPage.totalPages()).isEqualTo(2);
        assertThat(firstPage.first()).isTrue();
        assertThat(firstPage.last()).isFalse();
    }

    @Test
    void dashboardCountsAllMatchingRowsInsteadOfLoadedPageSize() {
        String suffix = UUID.randomUUID().toString();
        User guide = createProfile("DashboardGuide" + suffix, RoleType.ROLE_GUIDE, AccountStatus.ACTIVE);
        User admin = createUser("DashboardAdmin" + suffix, RoleType.ROLE_ADMIN, AccountStatus.ACTIVE);
        MediaAsset cover = createCover(guide, suffix);
        Instant now = clock.instant();

        Tour approved = createTour(guide, cover, "Approved tour", now);
        approved.approve(admin, now);
        approved = tourRepository.saveAndFlush(approved);
        tourSessionRepository.saveAllAndFlush(List.of(
                TourSession.create(
                        approved,
                        "First meeting point",
                        now.plus(5, ChronoUnit.DAYS),
                        90,
                        5_000,
                        "USD",
                        5,
                        TourSessionStatus.OPEN_FOR_BOOKING
                ),
                TourSession.create(
                        approved,
                        "Second meeting point",
                        now.plus(6, ChronoUnit.DAYS),
                        90,
                        5_000,
                        "USD",
                        5,
                        TourSessionStatus.OPEN_FOR_BOOKING
                )
        ));
        tourRepository.saveAllAndFlush(List.of(
                createTour(guide, cover, "Pending tour one", now),
                createTour(guide, cover, "Pending tour two", now)
        ));

        GuideDashboardResponse dashboard = guideDashboardService.getDashboard(guide);

        assertThat(dashboard.activeSessionCount()).isEqualTo(2);
        assertThat(dashboard.pendingReviewCount()).isEqualTo(2);
        assertThat(dashboard.currencyCode()).isEqualTo("USD");
    }

    @Test
    void topGuidesUsesDatabaseRankingFiltersAndLimit() {
        String suffix = UUID.randomUUID().toString();
        User admin = createUser("RankingAdmin" + suffix, RoleType.ROLE_ADMIN, AccountStatus.ACTIVE);
        User mostCompleted = createProfile(
                "RankingFirst" + suffix,
                RoleType.ROLE_GUIDE,
                AccountStatus.ACTIVE
        );
        User second = createProfile(
                "RankingSecond" + suffix,
                RoleType.ROLE_GUIDE,
                AccountStatus.ACTIVE
        );
        User disabled = createProfile(
                "RankingDisabled" + suffix,
                RoleType.ROLE_GUIDE,
                AccountStatus.DISABLED
        );
        createCompletedSessions(mostCompleted, admin, suffix + "-first", 2);
        createCompletedSessions(second, admin, suffix + "-second", 1);
        createCompletedSessions(disabled, admin, suffix + "-disabled", 3);

        List<GuideSearchItemResponse> topGuides = guideDiscoveryService.top(2);

        assertThat(topGuides).extracting(GuideSearchItemResponse::guideId)
                .containsExactly(mostCompleted.getId(), second.getId());
        assertThat(topGuides).extracting(GuideSearchItemResponse::completedSessionCount)
                .containsExactly(2L, 1L);
    }

    @Test
    void topGuidesUsesBayesianRatingInsteadOfRawAverage() {
        String suffix = UUID.randomUUID().toString();
        User admin = createUser("BayesianAdmin" + suffix, RoleType.ROLE_ADMIN, AccountStatus.ACTIVE);
        User oneFiveStarReview = createProfile(
                "BayesianFive" + suffix,
                RoleType.ROLE_GUIDE,
                AccountStatus.ACTIVE
        );
        User tenFourStarReviews = createProfile(
                "BayesianFour" + suffix,
                RoleType.ROLE_GUIDE,
                AccountStatus.ACTIVE
        );
        createReviewedCompletedSession(oneFiveStarReview, admin, suffix + "-five", 5, 1);
        createReviewedCompletedSession(tenFourStarReviews, admin, suffix + "-four", 4, 10);

        List<GuideSearchItemResponse> topGuides = guideDiscoveryService.top(2);

        assertThat(topGuides).extracting(GuideSearchItemResponse::guideId)
                .containsExactly(tenFourStarReviews.getId(), oneFiveStarReview.getId());
        assertThat(topGuides).extracting(GuideSearchItemResponse::averageRating)
                .containsExactly(4.0, 5.0);
    }

    private User createProfile(String specialty, RoleType roleType, AccountStatus status) {
        User user = createUser(specialty, roleType, status);
        guideProfileRepository.saveAndFlush(GuideProfile.create(
                user,
                specialty.substring(0, Math.min(specialty.length(), 60)),
                "A complete biography used to validate public guide projection behavior.",
                List.of("en")
        ));
        return user;
    }

    private User createUser(String seed, RoleType roleType, AccountStatus status) {
        Role role = roleRepository.findByName(roleType.name()).orElseThrow();
        User user = new User();
        user.setFirstName(seed);
        user.setLastName("Projection");
        user.setEmail(seed.toLowerCase() + "-" + UUID.randomUUID() + "@example.com");
        user.setPassword("not-used");
        user.setRole(role);
        user.setRoleSelected(true);
        user.setAccountStatus(status);
        return userRepository.saveAndFlush(user);
    }

    private MediaAsset createCover(User guide, String suffix) {
        MediaAsset cover = MediaAsset.pending(
                guide,
                MediaPurpose.TOUR_COVER,
                "projection-cover-" + suffix + ".png",
                "cover.png",
                "image/png",
                100
        );
        cover.markReady();
        return mediaAssetRepository.saveAndFlush(cover);
    }

    private Tour createTour(User guide, MediaAsset cover, String title, Instant now) {
        return Tour.submit(
                guide,
                new TourChangeSnapshot(
                        title,
                        "A sufficiently detailed description for a dashboard projection test.",
                        "TR",
                        "istanbul-projection",
                        "Istanbul",
                        "Europe/Istanbul",
                        "culture",
                        List.of("en"),
                        cover.getId()
                ),
                cover,
                now
        );
    }

    private void createCompletedSessions(
            User guide,
            User admin,
            String suffix,
            int sessionCount
    ) {
        Instant now = clock.instant();
        MediaAsset cover = createCover(guide, suffix);
        Tour tour = createTour(guide, cover, "Ranked tour " + suffix, now);
        tour.approve(admin, now);
        tour = tourRepository.saveAndFlush(tour);
        for (int index = 0; index < sessionCount; index++) {
            tourSessionRepository.save(TourSession.create(
                    tour,
                    "Ranking meeting point " + index,
                    now.minus(index + 2L, ChronoUnit.DAYS),
                    60,
                    5_000,
                    "USD",
                    5,
                    TourSessionStatus.COMPLETED
            ));
        }
        tourSessionRepository.flush();
    }

    private void createReviewedCompletedSession(
            User guide,
            User admin,
            String suffix,
            int rating,
            int reviewCount
    ) {
        Instant now = clock.instant();
        MediaAsset cover = createCover(guide, suffix);
        Tour tour = createTour(guide, cover, "Reviewed tour " + suffix, now);
        tour.approve(admin, now);
        tour = tourRepository.saveAndFlush(tour);
        TourSession session = tourSessionRepository.saveAndFlush(TourSession.create(
                tour,
                "Reviewed meeting point",
                now.minus(2, ChronoUnit.DAYS),
                60,
                5_000,
                "USD",
                reviewCount,
                TourSessionStatus.COMPLETED
        ));
        for (int index = 0; index < reviewCount; index++) {
            User tourist = createUser(
                    "BayesianTourist" + suffix + index,
                    RoleType.ROLE_TOURIST,
                    AccountStatus.ACTIVE
            );
            Reservation reservation = Reservation.hold(
                    session,
                    tourist,
                    1,
                    5_000,
                    5_000,
                    "USD",
                    now.plus(10, ChronoUnit.MINUTES),
                    "FULL_REFUND_48_HOURS",
                    1,
                    1,
                    "{}",
                    "ranking-" + suffix + "-" + index
            );
            reservation.confirm();
            reservation.complete();
            reservation = reservationRepository.saveAndFlush(reservation);
            reviewRepository.save(Review.submit(reservation, rating, null));
        }
        reviewRepository.flush();
    }
}
