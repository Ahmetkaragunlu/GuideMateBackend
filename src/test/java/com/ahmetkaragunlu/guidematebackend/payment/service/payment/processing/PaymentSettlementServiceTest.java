package com.ahmetkaragunlu.guidematebackend.payment.service.payment.processing;

import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.service.refund.PaymentRefundService;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.reservation.service.finalization.ReservationFinalizationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.service.earning.GuideEarningLifecycleService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletEntryCommand;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentSettlementServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-13T00:00:00Z");

    @Mock private ReservationFinalizationService reservationFinalizationService;
    @Mock private PaymentRefundService refundService;
    @Mock private WalletAccountService walletAccountService;
    @Mock private GuideEarningLifecycleService guideEarningService;

    private PaymentSettlementService service;

    @BeforeEach
    void setUp() {
        service = new PaymentSettlementService(
                reservationFinalizationService,
                refundService,
                walletAccountService,
                guideEarningService,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void lateTourPaymentFinalizesWhenCapacityRemains() {
        SettlementFixture fixture = tourPaymentFixture(false);

        service.settleSuccessful(fixture.payment(), PaymentStatus.TIMEOUT);

        verify(reservationFinalizationService).finalizeAfterPaymentVerification(fixture.reservation().getId());
        verify(guideEarningService).createPending(fixture.reservation());
        verify(refundService, never()).requestFullRefund(any(), any(), any());
    }

    @Test
    void lateTourPaymentRequestsRefundWhenCapacityIsGone() {
        SettlementFixture fixture = tourPaymentFixture(true);
        when(fixture.payment().getId()).thenReturn(fixture.paymentId());
        when(fixture.payment().getUser()).thenReturn(fixture.user());

        service.settleSuccessful(fixture.payment(), PaymentStatus.TIMEOUT);

        verify(refundService).requestFullRefund(
                fixture.paymentId(),
                fixture.user(),
                "late-payment:" + fixture.paymentId()
        );
        verify(guideEarningService, never()).createPending(any());
    }

    @Test
    void cancelledTopUpRequestsRefundInsteadOfCreditingWallet() {
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        User user = org.mockito.Mockito.mock(User.class);
        UUID paymentId = UUID.randomUUID();
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getPurpose()).thenReturn(PaymentPurpose.WALLET_TOP_UP);
        when(payment.getUser()).thenReturn(user);

        service.settleSuccessful(payment, PaymentStatus.CANCELLED);

        verify(refundService).requestFullRefund(paymentId, user, "cancelled-top-up:" + paymentId);
        verify(walletAccountService, never()).credit(any(), any());
    }

    @Test
    void successfulTopUpCreditsCanonicalWalletAmount() {
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        User user = org.mockito.Mockito.mock(User.class);
        Wallet wallet = org.mockito.Mockito.mock(Wallet.class);
        UUID paymentId = UUID.randomUUID();
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getPurpose()).thenReturn(PaymentPurpose.WALLET_TOP_UP);
        when(payment.getUser()).thenReturn(user);
        when(payment.getAmountMinor()).thenReturn(10_000L);
        when(walletAccountService.getOrCreateForUpdate(user)).thenReturn(wallet);

        service.settleSuccessful(payment, PaymentStatus.VERIFYING);

        ArgumentCaptor<WalletEntryCommand> captor = ArgumentCaptor.forClass(WalletEntryCommand.class);
        verify(walletAccountService).credit(org.mockito.ArgumentMatchers.eq(wallet), captor.capture());
        assertThat(captor.getValue().amountMinor()).isEqualTo(10_000L);
        assertThat(captor.getValue().type()).isEqualTo(LedgerEntryType.TOP_UP);
        assertThat(captor.getValue().referenceId()).isEqualTo(paymentId);
        assertThat(captor.getValue().occurredAt()).isEqualTo(NOW);
    }

    private SettlementFixture tourPaymentFixture(boolean refundRequired) {
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        User user = org.mockito.Mockito.mock(User.class);
        UUID paymentId = UUID.randomUUID();
        UUID reservationId = UUID.randomUUID();
        when(payment.getPurpose()).thenReturn(PaymentPurpose.TOUR_BOOKING);
        when(payment.getReservation()).thenReturn(reservation);
        when(reservation.getId()).thenReturn(reservationId);
        when(reservationFinalizationService.finalizeAfterPaymentVerification(reservationId))
                .thenReturn(new ReservationFinalizationResult(reservation, refundRequired));
        return new SettlementFixture(paymentId, payment, reservation, user);
    }

    private record SettlementFixture(UUID paymentId, Payment payment, Reservation reservation, User user) {
    }
}
