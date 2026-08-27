package com.ahmetkaragunlu.guidematebackend.tour;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequest;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewSummaryResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.AdminTourReviewType;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.service.AdminTourReviewQueryService;
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
class AdminTourReviewRepositoryIntegrationTest {

    @Autowired
    private AdminTourReviewQueryService reviewService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private MediaAssetRepository mediaAssetRepository;
    @Autowired
    private TourRepository tourRepository;
    @Autowired
    private TourChangeRequestRepository changeRequestRepository;
    @Autowired
    private Clock clock;

    @Test
    void combinesNewToursAndChangesWithDatabaseOrderingAndPaging() {
        Instant now = clock.instant();
        User guide = createUser(RoleType.ROLE_GUIDE, "ReviewGuide");
        User admin = createUser(RoleType.ROLE_ADMIN, "ReviewAdmin");
        MediaAsset cover = createCover(guide);
        Tour approvedTour = createTour(guide, cover, "Published title", now.minus(4, ChronoUnit.DAYS));
        approvedTour.approve(admin, now.minus(3, ChronoUnit.DAYS));
        approvedTour = tourRepository.saveAndFlush(approvedTour);
        TourChangeRequest changeRequest = changeRequestRepository.saveAndFlush(TourChangeRequest.submit(
                approvedTour,
                approvedTour.getVersion(),
                "{\"title\":\"Updated title\"}",
                cover,
                guide,
                now.minus(1, ChronoUnit.HOURS)
        ));
        Tour newTour = tourRepository.saveAndFlush(createTour(
                guide,
                cover,
                "New tour title",
                now.minus(2, ChronoUnit.HOURS)
        ));

        PageResponse<AdminTourReviewSummaryResponse> firstPage = reviewService.getPendingReviews(0, 1);
        PageResponse<AdminTourReviewSummaryResponse> secondPage = reviewService.getPendingReviews(1, 1);

        assertThat(firstPage.totalElements()).isEqualTo(2);
        assertThat(firstPage.totalPages()).isEqualTo(2);
        assertThat(firstPage.content()).singleElement().satisfies(review -> {
            assertThat(review.reviewId()).isEqualTo(changeRequest.getId());
            assertThat(review.type()).isEqualTo(AdminTourReviewType.TOUR_CHANGE);
            assertThat(review.title()).isEqualTo("Updated title");
        });
        assertThat(secondPage.content()).singleElement().satisfies(review -> {
            assertThat(review.reviewId()).isEqualTo(newTour.getId());
            assertThat(review.type()).isEqualTo(AdminTourReviewType.NEW_TOUR);
            assertThat(review.title()).isEqualTo("New tour title");
        });
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

    private MediaAsset createCover(User guide) {
        MediaAsset cover = MediaAsset.pending(
                guide,
                MediaPurpose.TOUR_COVER,
                "admin-review-" + UUID.randomUUID() + ".png",
                "cover.png",
                "image/png",
                100
        );
        cover.markReady();
        return mediaAssetRepository.saveAndFlush(cover);
    }

    private Tour createTour(User guide, MediaAsset cover, String title, Instant submittedAt) {
        return Tour.submit(
                guide,
                new TourChangeSnapshot(
                        title,
                        "A sufficiently detailed description for an admin review query test.",
                        "TR",
                        "istanbul-admin-review",
                        "Istanbul",
                        "Europe/Istanbul",
                        "culture",
                        List.of("en"),
                        cover.getId()
                ),
                cover,
                submittedAt
        );
    }
}
