package com.ahmetkaragunlu.guidematebackend.persistence;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.domain.MediaPurpose;
import com.ahmetkaragunlu.guidematebackend.media.repository.MediaAssetRepository;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentIntentService;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.CancelReservationRequest;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationCancellationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationService;
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
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WalletLedgerRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletAccountService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
class PersistenceConcurrencyIntegrationTest {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private WalletAccountService walletAccountService;
    @Autowired
    private WalletLedgerRepository walletLedgerRepository;
    @Autowired
    private PaymentIntentService paymentIntentService;
    @Autowired
    private PaymentRepository paymentRepository;
    @Autowired
    private ReservationRepository reservationRepository;
    @Autowired
    private GuideEarningRepository guideEarningRepository;
    @Autowired
    private RefundRepository refundRepository;
    @Autowired
    private ReservationService reservationService;
    @Autowired
    private ReservationBookingService reservationBookingService;
    @Autowired
    private ReservationCapacityService reservationCapacityService;
    @Autowired
    private MediaAssetRepository mediaAssetRepository;
    @Autowired
    private GuideProfileRepository guideProfileRepository;
    @Autowired
    private TourRepository tourRepository;
    @Autowired
    private TourSessionRepository tourSessionRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private Clock clock;

    @Test
    void preventsConcurrentWalletOverspend() throws Exception {
        WalletFixture fixture = createFundedWallet(10_000L);

        List<ErrorCode> results = runConcurrently(
                () -> debit(fixture.userId(), 8_000L, "debit-a-" + UUID.randomUUID()),
                () -> debit(fixture.userId(), 8_000L, "debit-b-" + UUID.randomUUID())
        );

        assertThat(results.stream().filter(result -> result == null).count()).isEqualTo(1);
        assertThat(results.stream().filter(ErrorCode.INSUFFICIENT_WALLET_BALANCE::equals).count())
                .isEqualTo(1);
        assertThat(walletBalance(fixture.userId()).availableBalanceMinor()).isEqualTo(2_000L);
        assertThat(walletLedgerRepository.findByWallet_IdOrderByOccurredAtDesc(
                fixture.walletId(),
                org.springframework.data.domain.PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(2);
    }

    @Test
    void appliesConcurrentWalletRetryOnlyOnce() throws Exception {
        WalletFixture fixture = createFundedWallet(10_000L);
        String idempotencyKey = "same-debit-" + UUID.randomUUID();

        List<ErrorCode> results = runConcurrently(
                () -> debit(fixture.userId(), 3_000L, idempotencyKey),
                () -> debit(fixture.userId(), 3_000L, idempotencyKey)
        );

        assertThat(results).containsOnlyNulls();
        assertThat(walletBalance(fixture.userId()).availableBalanceMinor()).isEqualTo(7_000L);
        assertThat(walletLedgerRepository.findByWallet_IdOrderByOccurredAtDesc(
                fixture.walletId(),
                org.springframework.data.domain.PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(2);
    }

    @Test
    void preventsConcurrentReservationsFromExceedingCapacity() throws Exception {
        ReservationFixture fixture = createReservationFixture();

        List<ReservationAttempt> attempts = runConcurrently(
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
        ReservationFixture fixture = createReservationFixture();
        String idempotencyKey = "same-hold-" + UUID.randomUUID();

        List<ReservationAttempt> attempts = runConcurrently(
                () -> createHold(fixture.firstTouristEmail(), fixture.sessionId(), idempotencyKey),
                () -> createHold(fixture.firstTouristEmail(), fixture.sessionId(), idempotencyKey)
        );

        assertThat(attempts).allMatch(attempt -> attempt.errorCode() == null);
        assertThat(attempts).extracting(ReservationAttempt::reservationId).doesNotContainNull();
        assertThat(attempts.get(0).reservationId()).isEqualTo(attempts.get(1).reservationId());
    }

    @Test
    void walletPurchaseCommitsPaymentReservationLedgerAndEarningOnlyOnce() {
        ReservationFixture fixture = createReservationFixture();
        WalletFixture wallet = fundUser(fixture.firstTouristEmail(), 15_000L);
        String idempotencyKey = "wallet-purchase-" + UUID.randomUUID();

        Payment first = purchaseWithWallet(fixture.firstTouristEmail(), fixture.sessionId(), idempotencyKey);
        Payment retry = purchaseWithWallet(fixture.firstTouristEmail(), fixture.sessionId(), idempotencyKey);

        assertThat(retry.getId()).isEqualTo(first.getId());
        Payment persistedPayment = paymentRepository.findById(first.getId()).orElseThrow();
        Reservation reservation = reservationRepository.findById(first.getReservation().getId()).orElseThrow();
        assertThat(persistedPayment.getMethod()).isEqualTo(PaymentMethod.WALLET);
        assertThat(persistedPayment.getStatus()).isEqualTo(PaymentStatus.SUCCEEDED);
        assertThat(reservation.getStatus()).isEqualTo(ReservationStatus.CONFIRMED);
        assertThat(walletBalance(wallet.userId()).availableBalanceMinor()).isEqualTo(5_000L);
        assertThat(walletLedgerRepository.findByWallet_IdOrderByOccurredAtDesc(
                wallet.walletId(),
                org.springframework.data.domain.PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(2);
        assertThat(guideEarningRepository.findByReservation_Id(reservation.getId())).isPresent();
    }

    @Test
    void insufficientWalletBalanceRollsBackPaymentAndReservation() {
        ReservationFixture fixture = createReservationFixture();
        WalletFixture wallet = fundUser(fixture.firstTouristEmail(), 5_000L);
        String idempotencyKey = "wallet-rollback-" + UUID.randomUUID();

        assertThatThrownBy(() -> purchaseWithWallet(
                fixture.firstTouristEmail(),
                fixture.sessionId(),
                idempotencyKey
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INSUFFICIENT_WALLET_BALANCE));

        User tourist = userRepository.findByEmailWithRole(fixture.firstTouristEmail()).orElseThrow();
        assertThat(paymentRepository.findByUser_IdAndPurposeAndIdempotencyKey(
                tourist.getId(),
                com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose.TOUR_BOOKING,
                idempotencyKey
        )).isEmpty();
        assertThat(reservationRepository.findByTourist_IdAndIdempotencyKey(tourist.getId(), idempotencyKey))
                .isEmpty();
        assertThat(reservationCapacityService.occupiedCount(fixture.sessionId())).isZero();
        assertThat(walletBalance(wallet.userId()).availableBalanceMinor()).isEqualTo(5_000L);
        assertThat(walletLedgerRepository.findByWallet_IdOrderByOccurredAtDesc(
                wallet.walletId(),
                org.springframework.data.domain.PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(1);
    }

    @Test
    void walletCancellationRefundsLedgerAndReversesEarningOnlyOnce() {
        ReservationFixture fixture = createReservationFixture();
        WalletFixture wallet = fundUser(fixture.firstTouristEmail(), 15_000L);
        Payment payment = purchaseWithWallet(
                fixture.firstTouristEmail(),
                fixture.sessionId(),
                "wallet-cancel-purchase-" + UUID.randomUUID()
        );
        User tourist = userRepository.findByEmailWithRole(fixture.firstTouristEmail()).orElseThrow();
        Reservation reservation = reservationRepository.findById(payment.getReservation().getId()).orElseThrow();
        String cancellationKey = "wallet-cancel-" + UUID.randomUUID();

        ReservationCancellationResponse first = reservationService.cancel(
                tourist,
                reservation.getId(),
                cancellationKey,
                new CancelReservationRequest(reservation.getVersion(), "Plans changed")
        );
        ReservationCancellationResponse retry = reservationService.cancel(
                tourist,
                reservation.getId(),
                cancellationKey,
                new CancelReservationRequest(reservation.getVersion(), "Plans changed")
        );

        assertThat(retry.refundId()).isEqualTo(first.refundId());
        assertThat(first.refundStatus()).isEqualTo(RefundStatus.SUCCEEDED);
        assertThat(reservationRepository.findById(reservation.getId()).orElseThrow().getStatus())
                .isEqualTo(ReservationStatus.CANCELLED);
        assertThat(refundRepository.findFirstByPayment_IdOrderByCreatedAtDesc(payment.getId()))
                .hasValueSatisfying(refund -> assertThat(refund.getId()).isEqualTo(first.refundId()));
        assertThat(guideEarningRepository.findByReservation_Id(reservation.getId()))
                .hasValueSatisfying(earning -> assertThat(earning.getStatus())
                        .isEqualTo(GuideEarningStatus.REVERSED));
        assertThat(walletBalance(wallet.userId()).availableBalanceMinor()).isEqualTo(15_000L);
        assertThat(walletLedgerRepository.findByWallet_IdOrderByOccurredAtDesc(
                wallet.walletId(),
                org.springframework.data.domain.PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(3);
    }

    private WalletFixture createFundedWallet(long amountMinor) {
        return transactionTemplate().execute(status -> {
            User user = createUser("wallet-" + UUID.randomUUID() + "@example.com", RoleType.ROLE_TOURIST);
            Wallet wallet = walletAccountService.getOrCreateForUpdate(user);
            walletAccountService.credit(
                    wallet,
                    amountMinor,
                    LedgerEntryType.TOP_UP,
                    "TEST_SETUP",
                    UUID.randomUUID(),
                    "seed-" + UUID.randomUUID(),
                    clock.instant()
            );
            walletLedgerRepository.flush();
            return new WalletFixture(user.getId(), wallet.getId());
        });
    }

    private WalletFixture fundUser(String email, long amountMinor) {
        return transactionTemplate().execute(status -> {
            User user = userRepository.findByEmailWithRole(email).orElseThrow();
            Wallet wallet = walletAccountService.getOrCreateForUpdate(user);
            walletAccountService.credit(
                    wallet,
                    amountMinor,
                    LedgerEntryType.TOP_UP,
                    "TEST_SETUP",
                    UUID.randomUUID(),
                    "seed-" + UUID.randomUUID(),
                    clock.instant()
            );
            walletLedgerRepository.flush();
            return new WalletFixture(user.getId(), wallet.getId());
        });
    }

    private Payment purchaseWithWallet(String email, UUID sessionId, String idempotencyKey) {
        User tourist = userRepository.findByEmailWithRole(email).orElseThrow();
        return paymentIntentService.purchaseTourWithWallet(tourist, sessionId, 1, idempotencyKey);
    }

    private ErrorCode debit(Long userId, long amountMinor, String idempotencyKey) {
        try {
            transactionTemplate().executeWithoutResult(status -> {
                User user = userRepository.findById(userId).orElseThrow();
                Wallet wallet = walletAccountService.getOrCreateForUpdate(user);
                walletAccountService.debit(
                        wallet,
                        amountMinor,
                        LedgerEntryType.TOUR_PURCHASE,
                        "TEST_PURCHASE",
                        UUID.randomUUID(),
                        idempotencyKey,
                        clock.instant()
                );
                walletLedgerRepository.flush();
            });
            return null;
        } catch (BusinessException exception) {
            return exception.getErrorCode();
        }
    }

    private com.ahmetkaragunlu.guidematebackend.wallet.service.WalletBalance walletBalance(Long userId) {
        User user = userRepository.findById(userId).orElseThrow();
        return walletAccountService.getBalance(user);
    }

    private ReservationFixture createReservationFixture() {
        return transactionTemplate().execute(status -> {
            String suffix = UUID.randomUUID().toString();
            User guide = createUser("guide-" + suffix + "@example.com", RoleType.ROLE_GUIDE);
            User admin = createUser("admin-" + suffix + "@example.com", RoleType.ROLE_ADMIN);
            User firstTourist = createUser("tourist-a-" + suffix + "@example.com", RoleType.ROLE_TOURIST);
            User secondTourist = createUser("tourist-b-" + suffix + "@example.com", RoleType.ROLE_TOURIST);

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
        });
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

    private User createUser(String email, RoleType roleType) {
        Role role = roleRepository.findByName(roleType.name()).orElseThrow();
        User user = new User();
        user.setFirstName("Test");
        user.setLastName(roleType.name());
        user.setEmail(email);
        user.setPassword("not-used");
        user.setRole(role);
        user.setRoleSelected(true);
        user.setAccountStatus(AccountStatus.ACTIVE);
        return userRepository.saveAndFlush(user);
    }

    private TransactionTemplate transactionTemplate() {
        return new TransactionTemplate(transactionManager);
    }

    private <T> List<T> runConcurrently(Callable<T> first, Callable<T> second) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<T> firstFuture = executor.submit(gated(first, ready, start));
            Future<T> secondFuture = executor.submit(gated(second, ready, start));
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            return Arrays.asList(
                    firstFuture.get(10, TimeUnit.SECONDS),
                    secondFuture.get(10, TimeUnit.SECONDS)
            );
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }

    private <T> Callable<T> gated(Callable<T> task, CountDownLatch ready, CountDownLatch start) {
        return () -> {
            ready.countDown();
            if (!start.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Concurrent test start timed out");
            }
            return task.call();
        };
    }

    private record WalletFixture(Long userId, UUID walletId) {
    }

    private record ReservationFixture(
            UUID sessionId,
            String firstTouristEmail,
            String secondTouristEmail
    ) {
    }

    private record ReservationAttempt(UUID reservationId, ErrorCode errorCode) {
    }
}
