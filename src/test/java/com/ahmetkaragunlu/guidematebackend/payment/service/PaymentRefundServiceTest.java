package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletAccountService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.util.ReflectionTestUtils;

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
class PaymentRefundServiceTest {

    @Mock
    private PaymentRepository paymentRepository;
    @Mock
    private RefundRepository refundRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private WalletAccountService walletAccountService;
    @Mock
    private ApplicationEventPublisher eventPublisher;
    @Mock
    private RefundNotificationPublisher refundNotificationPublisher;

    private PaymentRefundService service;

    @BeforeEach
    void setUp() {
        service = new PaymentRefundService(
                paymentRepository,
                refundRepository,
                userRepository,
                walletAccountService,
                eventPublisher,
                refundNotificationPublisher,
                Clock.fixed(Instant.parse("2026-08-13T00:00:00Z"), ZoneOffset.UTC)
        );
    }

    @Test
    void refundsRemainingProviderChargeInOriginalCurrency() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        User user = org.mockito.Mockito.mock(User.class);
        when(user.getId()).thenReturn(42L);
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getStatus()).thenReturn(PaymentStatus.SUCCEEDED);
        when(payment.getMethod()).thenReturn(PaymentMethod.HOSTED_CARD);
        when(payment.getAmountMinor()).thenReturn(1_000L);
        when(payment.getCurrencyCode()).thenReturn("USD");
        when(payment.getChargeAmountMinor()).thenReturn(47_758L);
        when(payment.getChargeCurrencyCode()).thenReturn("TRY");
        when(payment.getProviderTransactionId()).thenReturn("provider-transaction");
        when(refundRepository.findByPayment_IdAndIdempotencyKey(paymentId, "refund-key"))
                .thenReturn(Optional.empty());
        when(refundRepository.sumAmountByPaymentAndStatuses(any(), any())).thenReturn(0L);
        when(refundRepository.sumChargeAmountByPaymentAndStatuses(any(), any())).thenReturn(0L);
        when(userRepository.getReferenceById(42L)).thenReturn(user);
        when(refundRepository.saveAndFlush(any(Refund.class)))
                .thenAnswer(invocation -> {
                    Refund refund = invocation.getArgument(0);
                    ReflectionTestUtils.setField(refund, "id", UUID.randomUUID());
                    return refund;
                });

        Refund refund = service.requestFullRefund(paymentId, user, "refund-key");

        assertThat(refund.getAmountMinor()).isEqualTo(1_000L);
        assertThat(refund.getCurrencyCode()).isEqualTo("USD");
        assertThat(refund.getChargeAmountMinor()).isEqualTo(47_758L);
        assertThat(refund.getChargeCurrencyCode()).isEqualTo("TRY");
    }

    @Test
    void returnsExistingRefundForSameIdempotencyKey() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        Refund previous = org.mockito.Mockito.mock(Refund.class);
        User user = org.mockito.Mockito.mock(User.class);
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getStatus()).thenReturn(PaymentStatus.SUCCEEDED);
        when(refundRepository.findByPayment_IdAndIdempotencyKey(paymentId, "same-refund"))
                .thenReturn(Optional.of(previous));

        Refund result = service.requestFullRefund(paymentId, user, "same-refund");

        assertThat(result).isSameAs(previous);
        verify(refundRepository, never()).saveAndFlush(any());
        verify(eventPublisher, never()).publishEvent(any());
    }
}
