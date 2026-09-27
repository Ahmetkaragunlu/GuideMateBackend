package com.ahmetkaragunlu.guidematebackend.payment;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.refund.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.checkout.WalletPaymentService;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.request.CancelReservationRequest;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.response.ReservationCancellationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.lifecycle.ReservationCancellationService;
import com.ahmetkaragunlu.guidematebackend.support.persistence.PersistenceTestFixtures;
import com.ahmetkaragunlu.guidematebackend.support.persistence.PersistenceTestFixtures.ReservationFixture;
import com.ahmetkaragunlu.guidematebackend.support.persistence.PersistenceTestFixtures.WalletFixture;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WalletLedgerRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletBalance;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@ActiveProfiles("test")
@Import(PersistenceTestFixtures.class)
class WalletPaymentTransactionIntegrationTest {

    @Autowired
    private PersistenceTestFixtures fixtures;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private WalletAccountService walletAccountService;
    @Autowired
    private WalletLedgerRepository walletLedgerRepository;
    @Autowired
    private WalletPaymentService walletPaymentService;
    @Autowired
    private PaymentRepository paymentRepository;
    @Autowired
    private ReservationRepository reservationRepository;
    @Autowired
    private GuideEarningRepository guideEarningRepository;
    @Autowired
    private RefundRepository refundRepository;
    @Autowired
    private ReservationCancellationService reservationCancellationService;
    @Autowired
    private ReservationCapacityService reservationCapacityService;

    @Test
    void walletPurchaseCommitsPaymentReservationLedgerAndEarningOnlyOnce() {
        ReservationFixture fixture = fixtures.createReservationFixture();
        WalletFixture wallet = fixtures.fundUser(fixture.firstTouristEmail(), 15_000L);
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
                PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(2);
        assertThat(guideEarningRepository.findByReservation_Id(reservation.getId())).isPresent();
    }

    @Test
    void insufficientWalletBalanceRollsBackPaymentAndReservation() {
        ReservationFixture fixture = fixtures.createReservationFixture();
        WalletFixture wallet = fixtures.fundUser(fixture.firstTouristEmail(), 5_000L);
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
                PaymentPurpose.TOUR_BOOKING,
                idempotencyKey
        )).isEmpty();
        assertThat(reservationRepository.findByTourist_IdAndIdempotencyKey(tourist.getId(), idempotencyKey))
                .isEmpty();
        assertThat(reservationCapacityService.occupiedCount(fixture.sessionId())).isZero();
        assertThat(walletBalance(wallet.userId()).availableBalanceMinor()).isEqualTo(5_000L);
        assertThat(walletLedgerRepository.findByWallet_IdOrderByOccurredAtDesc(
                wallet.walletId(),
                PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(1);
    }

    @Test
    void walletCancellationRefundsLedgerAndReversesEarningOnlyOnce() {
        ReservationFixture fixture = fixtures.createReservationFixture();
        WalletFixture wallet = fixtures.fundUser(fixture.firstTouristEmail(), 15_000L);
        Payment payment = purchaseWithWallet(
                fixture.firstTouristEmail(),
                fixture.sessionId(),
                "wallet-cancel-purchase-" + UUID.randomUUID()
        );
        User tourist = userRepository.findByEmailWithRole(fixture.firstTouristEmail()).orElseThrow();
        Reservation reservation = reservationRepository.findById(payment.getReservation().getId()).orElseThrow();
        String cancellationKey = "wallet-cancel-" + UUID.randomUUID();

        ReservationCancellationResponse first = reservationCancellationService.cancel(
                tourist,
                reservation.getId(),
                cancellationKey,
                new CancelReservationRequest(reservation.getVersion(), "Plans changed")
        );
        ReservationCancellationResponse retry = reservationCancellationService.cancel(
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
                PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(3);
    }

    private Payment purchaseWithWallet(String email, UUID sessionId, String idempotencyKey) {
        User tourist = userRepository.findByEmailWithRole(email).orElseThrow();
        return walletPaymentService.purchaseTour(tourist, sessionId, 1, idempotencyKey);
    }

    private WalletBalance walletBalance(Long userId) {
        User user = userRepository.findById(userId).orElseThrow();
        return walletAccountService.getBalance(user);
    }
}
