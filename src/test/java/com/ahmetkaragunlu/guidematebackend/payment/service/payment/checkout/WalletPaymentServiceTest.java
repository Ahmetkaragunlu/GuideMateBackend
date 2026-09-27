package com.ahmetkaragunlu.guidematebackend.payment.service.payment.checkout;

import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.booking.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.reservation.service.finalization.ReservationFinalizationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
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
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WalletPaymentServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-27T09:00:00Z");

    @Mock private PaymentRepository paymentRepository;
    @Mock private UserRepository userRepository;
    @Mock private ReservationBookingService reservationBookingService;
    @Mock private ReservationFinalizationService reservationFinalizationService;
    @Mock private WalletAccountService walletAccountService;
    @Mock private GuideEarningLifecycleService guideEarningService;
    @Mock private IdempotencyKeyPolicy idempotencyKeyPolicy;

    private WalletPaymentService service;

    @BeforeEach
    void setUp() {
        service = new WalletPaymentService(
                paymentRepository,
                userRepository,
                reservationBookingService,
                reservationFinalizationService,
                walletAccountService,
                guideEarningService,
                idempotencyKeyPolicy,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void purchasesTourAndFinalizesReservationAtomically() {
        UUID sessionId = UUID.randomUUID();
        User tourist = org.mockito.Mockito.mock(User.class);
        User userReference = org.mockito.Mockito.mock(User.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        Wallet wallet = org.mockito.Mockito.mock(Wallet.class);
        when(tourist.getId()).thenReturn(42L);
        when(idempotencyKeyPolicy.normalize("wallet-key")).thenReturn("wallet-key");
        when(reservationBookingService.createHold(tourist, sessionId, 2, "wallet-key"))
                .thenReturn(reservation);
        when(reservation.getId()).thenReturn(UUID.randomUUID());
        when(reservation.getTotalPriceMinor()).thenReturn(10_000L);
        when(reservation.getCurrencyCode()).thenReturn("USD");
        when(paymentRepository.findByUser_IdAndPurposeAndIdempotencyKey(
                42L,
                PaymentPurpose.TOUR_BOOKING,
                "wallet-key"
        )).thenReturn(Optional.empty());
        when(userRepository.getReferenceById(42L)).thenReturn(userReference);
        when(walletAccountService.getOrCreateForUpdate(tourist)).thenReturn(wallet);
        when(paymentRepository.saveAndFlush(any(Payment.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(reservationFinalizationService.finalizeAfterPaymentVerification(reservation.getId()))
                .thenReturn(new ReservationFinalizationResult(reservation, false));

        Payment payment = service.purchaseTour(tourist, sessionId, 2, "wallet-key");

        assertThat(payment.getMethod()).isEqualTo(PaymentMethod.WALLET);
        assertThat(payment.getAmountMinor()).isEqualTo(10_000L);
        ArgumentCaptor<WalletEntryCommand> commandCaptor = ArgumentCaptor.forClass(WalletEntryCommand.class);
        verify(walletAccountService).debit(org.mockito.ArgumentMatchers.eq(wallet), commandCaptor.capture());
        assertThat(commandCaptor.getValue().amountMinor()).isEqualTo(10_000L);
        assertThat(commandCaptor.getValue().type()).isEqualTo(LedgerEntryType.TOUR_PURCHASE);
        assertThat(commandCaptor.getValue().occurredAt()).isEqualTo(NOW);
        verify(guideEarningService).createPending(reservation);
    }

    @Test
    void returnsMatchingIdempotentWalletPaymentWithoutSecondDebit() {
        UUID sessionId = UUID.randomUUID();
        User tourist = org.mockito.Mockito.mock(User.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        Payment previous = org.mockito.Mockito.mock(Payment.class);
        when(tourist.getId()).thenReturn(42L);
        when(idempotencyKeyPolicy.normalize("wallet-key")).thenReturn("wallet-key");
        when(reservationBookingService.createHold(tourist, sessionId, 1, "wallet-key"))
                .thenReturn(reservation);
        when(reservation.getId()).thenReturn(UUID.randomUUID());
        when(reservation.getTotalPriceMinor()).thenReturn(5_000L);
        when(previous.getMethod()).thenReturn(PaymentMethod.WALLET);
        when(previous.getAmountMinor()).thenReturn(5_000L);
        when(previous.getReservation()).thenReturn(reservation);
        when(paymentRepository.findByUser_IdAndPurposeAndIdempotencyKey(
                42L,
                PaymentPurpose.TOUR_BOOKING,
                "wallet-key"
        )).thenReturn(Optional.of(previous));

        Payment result = service.purchaseTour(tourist, sessionId, 1, "wallet-key");

        assertThat(result).isSameAs(previous);
        verify(walletAccountService, never()).debit(any(), any());
        verify(paymentRepository, never()).saveAndFlush(any());
    }

}
