package com.ahmetkaragunlu.guidematebackend.support.persistence;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.change.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.tour.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WalletLedgerRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletEntryCommand;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@TestComponent
@RequiredArgsConstructor
public class PersistenceTestFixtures {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final WalletAccountService walletAccountService;
    private final WalletLedgerRepository walletLedgerRepository;
    private final MediaAssetRepository mediaAssetRepository;
    private final GuideProfileRepository guideProfileRepository;
    private final TourRepository tourRepository;
    private final TourSessionRepository tourSessionRepository;
    private final PlatformTransactionManager transactionManager;
    private final Clock clock;

    public WalletFixture createFundedWallet() {
        return Objects.requireNonNull(transactionTemplate().execute(status -> {
            User user = persistUser(
                    "wallet-" + UUID.randomUUID() + "@example.com",
                    RoleType.ROLE_TOURIST
            );
            return fund(user, 10_000L);
        }));
    }

    public WalletFixture fundUser(String email, long amountMinor) {
        return Objects.requireNonNull(transactionTemplate().execute(status -> {
            User user = userRepository.findByEmailWithRole(email).orElseThrow();
            return fund(user, amountMinor);
        }));
    }

    public ReservationFixture createReservationFixture() {
        return Objects.requireNonNull(transactionTemplate().execute(status -> {
            String suffix = UUID.randomUUID().toString();
            User guide = persistUser("guide-" + suffix + "@example.com", RoleType.ROLE_GUIDE);
            User admin = persistUser("admin-" + suffix + "@example.com", RoleType.ROLE_ADMIN);
            User firstTourist = persistUser("tourist-a-" + suffix + "@example.com", RoleType.ROLE_TOURIST);
            User secondTourist = persistUser("tourist-b-" + suffix + "@example.com", RoleType.ROLE_TOURIST);

            MediaAsset cover = MediaAsset.pending(
                    guide,
                    MediaPurpose.TOUR_COVER,
                    "test-cover-" + suffix + ".png",
                    "cover.png",
                    "image/png",
                    100
            );
            cover.markReady();
            cover = mediaAssetRepository.saveAndFlush(cover);
            guideProfileRepository.saveAndFlush(GuideProfile.create(
                    guide,
                    "Local guide",
                    "Experienced local guide for integration testing.",
                    List.of("en")
            ));

            Instant now = clock.instant();
            Tour tour = Tour.submit(
                    guide,
                    new TourChangeSnapshot(
                            "Concurrency tour",
                            "A sufficiently detailed tour description for integration testing.",
                            "TR",
                            "istanbul-test",
                            "Istanbul",
                            "Europe/Istanbul",
                            "culture",
                            List.of("en"),
                            cover.getId()
                    ),
                    cover,
                    now
            );
            tour.approve(admin, now);
            tour = tourRepository.saveAndFlush(tour);
            TourSession session = tourSessionRepository.saveAndFlush(TourSession.create(
                    tour,
                    "Test meeting point",
                    now.plus(7, ChronoUnit.DAYS),
                    120,
                    10_000L,
                    "USD",
                    1,
                    TourSessionStatus.OPEN_FOR_BOOKING
            ));
            return new ReservationFixture(
                    session.getId(),
                    firstTourist.getEmail(),
                    secondTourist.getEmail()
            );
        }));
    }

    public User createUser(String email, RoleType roleType) {
        return Objects.requireNonNull(transactionTemplate().execute(status -> persistUser(email, roleType)));
    }

    private WalletFixture fund(User user, long amountMinor) {
        Wallet wallet = walletAccountService.getOrCreateForUpdate(user);
        walletAccountService.credit(
                wallet,
                new WalletEntryCommand(
                        amountMinor,
                        LedgerEntryType.TOP_UP,
                        "TEST_SETUP",
                        UUID.randomUUID(),
                        "seed-" + UUID.randomUUID(),
                        clock.instant()
                )
        );
        walletLedgerRepository.flush();
        return new WalletFixture(user.getId(), wallet.getId());
    }

    private User persistUser(String email, RoleType roleType) {
        Role role = roleRepository.findByName(roleType.name()).orElseThrow();
        User user = new User("Test", roleType.name(), email, "not-used");
        user.activate();
        user.selectRole(role);
        return userRepository.saveAndFlush(user);
    }

    private TransactionTemplate transactionTemplate() {
        return new TransactionTemplate(transactionManager);
    }

    public record WalletFixture(Long userId, UUID walletId) {
    }

    public record ReservationFixture(
            UUID sessionId,
            String firstTouristEmail,
            String secondTouristEmail
    ) {
    }
}
