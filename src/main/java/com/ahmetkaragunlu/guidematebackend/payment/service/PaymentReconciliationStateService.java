package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.config.SchedulerProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.EnumSet;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentReconciliationStateService {

    private static final EnumSet<PaymentStatus> RECONCILABLE_STATUSES = EnumSet.of(
            PaymentStatus.REQUIRES_ACTION,
            PaymentStatus.VERIFYING,
            PaymentStatus.TIMEOUT
    );

    private final PaymentRepository paymentRepository;
    private final SchedulerProperties properties;
    private final Clock clock;

    @Transactional
    public boolean begin(UUID paymentId) {
        Payment payment = paymentRepository.findByIdForUpdate(paymentId).orElse(null);
        Instant now = clock.instant();
        if (payment == null
                || !RECONCILABLE_STATUSES.contains(payment.getStatus())
                || payment.getExpiresAt() == null
                || payment.getExpiresAt().isAfter(now)
                || payment.getReconciliationAttemptCount() >= properties.paymentMaxAttempts()
                || wasAttemptedRecently(payment, now)) {
            return false;
        }
        payment.markReconciliationAttempt(now);
        return true;
    }

    @Transactional
    public void markUncertain(UUID paymentId) {
        paymentRepository.findByIdForUpdate(paymentId)
                .ifPresent(Payment::markReconciliationUncertain);
    }

    private boolean wasAttemptedRecently(Payment payment, Instant now) {
        return payment.getLastReconciliationAt() != null
                && payment.getLastReconciliationAt().plus(properties.paymentRetryDelay()).isAfter(now);
    }
}
