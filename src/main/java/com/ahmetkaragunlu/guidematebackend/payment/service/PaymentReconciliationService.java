package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentReconciliationService {

    private final PaymentRepository paymentRepository;
    private final PaymentVerificationService paymentVerificationService;
    private final SensitiveDataCipher dataCipher;

    public Payment reconcile(UUID paymentId) {
        Payment payment = paymentRepository.findById(paymentId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_NOT_FOUND));
        if (payment.getMethod() != PaymentMethod.HOSTED_CARD
                || payment.getProviderTokenEncrypted() == null) {
            throw new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED);
        }
        String token;
        try {
            token = dataCipher.decrypt(payment.getProviderTokenEncrypted());
        } catch (RuntimeException exception) {
            throw new BusinessException(ErrorCode.PAYMENT_VERIFICATION_FAILED);
        }
        return paymentVerificationService.verifyToken(
                token,
                "RECONCILIATION",
                paymentId.toString()
        );
    }
}
