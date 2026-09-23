package com.ahmetkaragunlu.guidematebackend.payment.service.webhook;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.dto.request.IyzicoWebhookRequest;
import com.ahmetkaragunlu.guidematebackend.payment.service.payment.PaymentVerificationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class IyzicoWebhookService {

    private final IyzicoWebhookSignatureVerifier signatureVerifier;
    private final PaymentVerificationService paymentVerificationService;

    public Payment handle(String signature, IyzicoWebhookRequest request) {
        if (!signatureVerifier.isValid(signature, request)) {
            throw new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED);
        }
        return paymentVerificationService.verifyToken(
                request.token(),
                "WEBHOOK",
                request.eventSeed()
        );
    }
}
