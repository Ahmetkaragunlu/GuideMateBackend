package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.common.validation.IdempotencyKeyPolicy;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedCheckoutSession;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletAccountService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentIntentServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-27T09:00:00Z");

    @Mock
    private PaymentRepository paymentRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private ReservationBookingService reservationBookingService;
    @Mock
    private WalletAccountService walletAccountService;
    @Mock
    private GuideEarningService guideEarningService;
    @Mock
    private IdempotencyKeyPolicy idempotencyKeyPolicy;
    @Mock
    private SensitiveDataCipher dataCipher;
    @Mock
    private PaymentQuoteStateService paymentQuoteStateService;

    private PaymentIntentService service;

    @BeforeEach
    void setUp() {
        service = new PaymentIntentService(
                paymentRepository,
                userRepository,
                reservationBookingService,
                walletAccountService,
                guideEarningService,
                idempotencyKeyPolicy,
                dataCipher,
                paymentQuoteStateService,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void completesPendingHostedInitializationWithEncryptedToken() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        HostedCheckoutSession session = new HostedCheckoutSession(
                "provider-token",
                "https://sandbox.example/checkout",
                Duration.ofMinutes(30)
        );
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getStatus()).thenReturn(PaymentStatus.PENDING);
        when(dataCipher.encrypt("provider-token")).thenReturn("encrypted-token");
        when(dataCipher.fingerprint("provider-token")).thenReturn("token-fingerprint");

        Payment result = service.completeInitialization(paymentId, session, "conversation-id");

        assertThat(result).isSameAs(payment);
        verify(payment).markRequiresAction(
                "encrypted-token",
                "token-fingerprint",
                "conversation-id",
                "https://sandbox.example/checkout",
                NOW.plus(Duration.ofMinutes(30))
        );
    }

    @Test
    void doesNotMutateAlreadyInitializedPaymentOnRetry() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        HostedCheckoutSession session = new HostedCheckoutSession(
                "provider-token",
                "https://sandbox.example/checkout",
                Duration.ofMinutes(30)
        );
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getStatus()).thenReturn(PaymentStatus.REQUIRES_ACTION);

        Payment result = service.completeInitialization(paymentId, session, "conversation-id");

        assertThat(result).isSameAs(payment);
        verify(dataCipher, never()).encrypt(any());
        verify(payment, never()).markRequiresAction(any(), any(), any(), any(), any());
    }

    @Test
    void failedInitializationExpiresItsReservationAfterLockingSession() {
        UUID paymentId = UUID.randomUUID();
        UUID reservationId = UUID.randomUUID();
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getStatus()).thenReturn(PaymentStatus.PENDING);
        when(payment.getReservation()).thenReturn(reservation);
        when(reservation.getId()).thenReturn(reservationId);

        service.failInitialization(paymentId, "CARD_DECLINED");

        verify(reservationBookingService).lockSessionForReservation(reservationId);
        verify(payment).fail("CARD_DECLINED");
        verify(reservationBookingService).expire(reservationId);
    }

    @Test
    void cancelRejectsPaymentOwnedByAnotherUserWithoutLeakingIt() {
        UUID paymentId = UUID.randomUUID();
        User currentUser = org.mockito.Mockito.mock(User.class);
        User owner = org.mockito.Mockito.mock(User.class);
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        when(currentUser.getId()).thenReturn(42L);
        when(owner.getId()).thenReturn(99L);
        when(payment.getUser()).thenReturn(owner);
        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));

        assertThatThrownBy(() -> service.cancel(currentUser, paymentId))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_NOT_FOUND));

        verify(payment, never()).cancel();
    }

    @Test
    void cancelRejectsSettledPayment() {
        UUID paymentId = UUID.randomUUID();
        User currentUser = org.mockito.Mockito.mock(User.class);
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        when(currentUser.getId()).thenReturn(42L);
        when(payment.getUser()).thenReturn(currentUser);
        when(payment.getStatus()).thenReturn(PaymentStatus.SUCCEEDED);
        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));

        assertThatThrownBy(() -> service.cancel(currentUser, paymentId))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_NOT_CANCELLABLE));

        verify(payment, never()).cancel();
    }
}
