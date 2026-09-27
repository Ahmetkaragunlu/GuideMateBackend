package com.ahmetkaragunlu.guidematebackend.payment.service.payment.processing;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.crypto.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.event.ProviderVerifiedEvent;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.VerifiedPaymentResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentEventRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.ProviderFailureCodeMapper;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
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
class PaymentResultServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-13T00:00:00Z");

    @Mock
    private PaymentRepository paymentRepository;
    @Mock
    private PaymentEventRepository paymentEventRepository;
    @Mock
    private ReservationBookingService reservationBookingService;
    @Mock
    private PaymentSettlementService settlementService;
    @Mock
    private ProviderFailureCodeMapper failureCodeMapper;
    @Mock
    private SensitiveDataCipher dataCipher;
    @Mock
    private PaymentNotificationPublisher notificationPublisher;

    private PaymentResultService service;

    @BeforeEach
    void setUp() {
        service = new PaymentResultService(
                paymentRepository,
                paymentEventRepository,
                reservationBookingService,
                settlementService,
                failureCodeMapper,
                dataCipher,
                notificationPublisher,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void delegatesSuccessfulPaymentSettlementAndNotification() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = paymentForVerification(paymentId);
        when(payment.getStatus()).thenReturn(PaymentStatus.TIMEOUT);
        when(payment.getChargeAmountMinor()).thenReturn(10_000L);
        when(payment.getChargeCurrencyCode()).thenReturn("USD");

        service.apply(
                paymentId,
                successfulProviderResult(),
                new ProviderVerifiedEvent("RECONCILIATION", "reconciliation:event", "payload-hash")
        );

        verify(payment).succeed("provider-payment-id", "provider-transaction-id", NOW);
        verify(settlementService).settleSuccessful(payment, PaymentStatus.TIMEOUT);
        verify(notificationPublisher).publish(payment, NotificationType.PAYMENT_SUCCEEDED);
        verify(paymentEventRepository).save(any());
    }

    @Test
    void rejectsSuccessfulProviderResultWithDifferentChargeAmount() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = paymentForVerification(paymentId);
        when(payment.getChargeAmountMinor()).thenReturn(9_000L);

        assertThatThrownBy(() -> service.apply(
                paymentId,
                new VerifiedPaymentResult(
                        true,
                        "checkout-token",
                        "conversation-id",
                        "provider-payment-id",
                        "provider-transaction-id",
                        9_001L,
                        "EUR",
                        "SUCCESS",
                        null,
                        null
                ),
                new ProviderVerifiedEvent("CALLBACK", "callback:event", "payload-hash")
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_VERIFICATION_FAILED));

        verify(payment, never()).succeed(any(), any(), any());
        verify(settlementService, never()).settleSuccessful(any(), any());
    }

    @Test
    void ignoresAlreadyRecordedProviderEventWithoutApplyingSettlementAgain() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = paymentForVerification(paymentId);
        when(payment.getChargeAmountMinor()).thenReturn(10_000L);
        when(payment.getChargeCurrencyCode()).thenReturn("USD");
        when(paymentEventRepository.existsByProviderEventId("webhook:event")).thenReturn(true);

        Payment result = service.apply(
                paymentId,
                successfulProviderResult(),
                new ProviderVerifiedEvent("WEBHOOK", "webhook:event", "payload-hash")
        );

        assertThat(result).isSameAs(payment);
        verify(payment, never()).succeed(any(), any(), any());
        verify(settlementService, never()).settleSuccessful(any(), any());
        verify(notificationPublisher, never()).publish(any(), any());
        verify(paymentEventRepository, never()).save(any());
    }

    @Test
    void verifiedDeclineFailsPaymentAndExpiresReservation() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = paymentForVerification(paymentId);
        when(payment.getStatus()).thenReturn(
                PaymentStatus.VERIFYING,
                PaymentStatus.VERIFYING,
                PaymentStatus.VERIFYING,
                PaymentStatus.VERIFYING,
                PaymentStatus.FAILED
        );
        when(failureCodeMapper.toStableCode("10051"))
                .thenReturn(ErrorCode.CARD_INSUFFICIENT_FUNDS.name());

        service.apply(
                paymentId,
                new VerifiedPaymentResult(
                        false,
                        "checkout-token",
                        "conversation-id",
                        null,
                        null,
                        0,
                        null,
                        "FAILURE",
                        "10051",
                        null
                ),
                new ProviderVerifiedEvent("CALLBACK", "callback:declined", "payload-hash")
        );

        verify(payment).fail(ErrorCode.CARD_INSUFFICIENT_FUNDS.name());
        verify(settlementService).expireReservationAfterFailure(payment);
        verify(notificationPublisher).publish(payment, NotificationType.PAYMENT_FAILED);
        verify(paymentEventRepository).save(any());
    }

    private Payment paymentForVerification(UUID paymentId) {
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getReservation()).thenReturn(reservation);
        when(payment.getProviderTokenEncrypted()).thenReturn("encrypted-token");
        when(payment.getProviderConversationId()).thenReturn("conversation-id");
        when(dataCipher.decrypt("encrypted-token")).thenReturn("checkout-token");
        return payment;
    }

    private VerifiedPaymentResult successfulProviderResult() {
        return new VerifiedPaymentResult(
                true,
                "checkout-token",
                "conversation-id",
                "provider-payment-id",
                "provider-transaction-id",
                10_000L,
                "USD",
                "SUCCESS",
                null,
                null
        );
    }
}
