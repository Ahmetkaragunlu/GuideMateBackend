package com.ahmetkaragunlu.guidematebackend.payment.service.webhook;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.dto.request.IyzicoWebhookRequest;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.PaymentVerificationService;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class IyzicoWebhookServiceTest {

    private final IyzicoWebhookSignatureVerifier signatureVerifier = mock(IyzicoWebhookSignatureVerifier.class);
    private final PaymentVerificationService verificationService = mock(PaymentVerificationService.class);
    private final IyzicoWebhookService service = new IyzicoWebhookService(signatureVerifier, verificationService);

    @Test
    void rejectsInvalidSignatureWithoutCallingProviderVerification() {
        IyzicoWebhookRequest request = request();
        when(signatureVerifier.isValid("invalid", request)).thenReturn(false);

        assertThatThrownBy(() -> service.handle("invalid", request))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_VERIFICATION_FAILED));
        verify(verificationService, never()).verifyToken(org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void forwardsVerifiedWebhookWithCanonicalSourceAndEventSeed() {
        IyzicoWebhookRequest request = request();
        Payment payment = mock(Payment.class);
        when(signatureVerifier.isValid("signature", request)).thenReturn(true);
        when(verificationService.verifyToken(request.token(), "WEBHOOK", request.eventSeed())).thenReturn(payment);

        assertThat(service.handle("signature", request)).isSameAs(payment);
        verify(verificationService).verifyToken(request.token(), "WEBHOOK", request.eventSeed());
    }

    private IyzicoWebhookRequest request() {
        return new IyzicoWebhookRequest("PAYMENT", "1", "payment-id", "token", "conversation", "SUCCESS");
    }
}
