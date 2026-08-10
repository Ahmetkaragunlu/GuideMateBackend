package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedPaymentGateway;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.PaymentGatewayException;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.VerifiedPaymentResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PaymentVerificationService {

    private static final int MAX_PROVIDER_TOKEN_LENGTH = 1024;

    private final PaymentRepository paymentRepository;
    private final PaymentIntentService paymentIntentService;
    private final PaymentResultService paymentResultService;
    private final HostedPaymentGateway paymentGateway;
    private final SensitiveDataCipher dataCipher;

    public Payment verifyToken(String token, String eventType, String eventSeed) {
        if (token == null || token.isBlank() || token.length() > MAX_PROVIDER_TOKEN_LENGTH) {
            throw new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED);
        }
        String normalizedToken = token.trim();
        String tokenFingerprint = dataCipher.fingerprint(normalizedToken);
        Payment payment = paymentRepository.findByProviderTokenFingerprint(tokenFingerprint)
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED));
        paymentIntentService.markVerifying(payment.getId());

        VerifiedPaymentResult result;
        try {
            result = paymentGateway.retrieve(normalizedToken, payment.getProviderConversationId());
        } catch (PaymentGatewayException exception) {
            throw new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED);
        }
        String payloadHash = dataCipher.fingerprint(String.join("|",
                nullToEmpty(result.providerPaymentId()),
                nullToEmpty(result.providerTransactionId()),
                String.valueOf(result.amountMinor()),
                nullToEmpty(result.currencyCode()),
                nullToEmpty(result.providerStatus())
        ));
        String providerEventId = eventType.toLowerCase() + ":" + dataCipher.fingerprint(String.join("|",
                eventSeed,
                nullToEmpty(result.providerPaymentId()),
                nullToEmpty(result.providerStatus())
        ));
        return paymentResultService.apply(
                payment.getId(),
                result,
                new ProviderVerifiedEvent(eventType, providerEventId, payloadHash)
        );
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
