package com.ahmetkaragunlu.guidematebackend.payment.service.recovery;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.crypto.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.PaymentVerificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentReconciliationServiceTest {

    @Mock private PaymentRepository paymentRepository;
    @Mock private PaymentVerificationService verificationService;
    @Mock private SensitiveDataCipher dataCipher;

    private PaymentReconciliationService service;

    @BeforeEach
    void setUp() {
        service = new PaymentReconciliationService(paymentRepository, verificationService, dataCipher);
    }

    @Test
    void verifiesDecryptedHostedCheckoutToken() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = mock(Payment.class);
        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getMethod()).thenReturn(PaymentMethod.HOSTED_CARD);
        when(payment.getProviderTokenEncrypted()).thenReturn("encrypted-token");
        when(dataCipher.decrypt("encrypted-token")).thenReturn("checkout-token");
        when(verificationService.verifyToken("checkout-token", "RECONCILIATION", paymentId.toString()))
                .thenReturn(payment);

        assertThat(service.reconcile(paymentId)).isSameAs(payment);
        verify(verificationService).verifyToken("checkout-token", "RECONCILIATION", paymentId.toString());
    }

    @Test
    void rejectsWalletPaymentWithoutCallingProvider() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = mock(Payment.class);
        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getMethod()).thenReturn(PaymentMethod.WALLET);

        assertError(() -> service.reconcile(paymentId), ErrorCode.PAYMENT_VERIFICATION_FAILED);
    }

    @Test
    void hidesTokenDecryptionFailureBehindStableError() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = mock(Payment.class);
        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getMethod()).thenReturn(PaymentMethod.HOSTED_CARD);
        when(payment.getProviderTokenEncrypted()).thenReturn("corrupt");
        when(dataCipher.decrypt("corrupt")).thenThrow(new IllegalArgumentException("cipher detail"));

        assertError(() -> service.reconcile(paymentId), ErrorCode.PAYMENT_VERIFICATION_FAILED);
    }

    private void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable action, ErrorCode code) {
        assertThatThrownBy(action)
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(code));
    }
}
