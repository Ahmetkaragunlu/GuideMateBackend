package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.dto.IyzicoWebhookRequest;
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
