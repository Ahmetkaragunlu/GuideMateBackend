package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.RefundEligibility;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Component
public class CancellationPolicy {

    private static final String FULL_REFUND_POLICY_CODE = "FULL_REFUND_48_HOURS";
    private static final int FULL_REFUND_POLICY_VERSION = 1;
    private static final Duration FULL_REFUND_WINDOW = Duration.ofHours(48);

    public String currentCode() {
        return FULL_REFUND_POLICY_CODE;
    }

    public int currentVersion() {
        return FULL_REFUND_POLICY_VERSION;
    }

    public RefundEligibility touristEligibility(Reservation reservation, Instant cancelledAt) {
        if (reservation.getStatus() == ReservationStatus.PENDING_PAYMENT) {
            return RefundEligibility.NOT_APPLICABLE;
        }
        requireSupportedPolicy(reservation);
        Duration remaining = Duration.between(cancelledAt, reservation.getSession().getStartsAt());
        return remaining.compareTo(FULL_REFUND_WINDOW) >= 0
                ? RefundEligibility.FULL_REFUND
                : RefundEligibility.NO_REFUND;
    }

    public RefundEligibility operatorEligibility(Reservation reservation) {
        return reservation.getStatus() == ReservationStatus.CONFIRMED
                ? RefundEligibility.FULL_REFUND
                : RefundEligibility.NOT_APPLICABLE;
    }

    private void requireSupportedPolicy(Reservation reservation) {
        boolean supported = FULL_REFUND_POLICY_CODE.equals(reservation.getCancellationPolicyCode())
                && reservation.getCancellationPolicyVersion() == FULL_REFUND_POLICY_VERSION;
        if (!supported) {
            throw new BusinessException(ErrorCode.DATA_CONFLICT);
        }
    }
}
