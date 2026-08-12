package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.dto.PaymentResponse;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentQueryService {

    private final PaymentRepository paymentRepository;
    private final RefundRepository refundRepository;

    @Transactional(readOnly = true)
    public PaymentResponse getOwned(User currentUser, UUID paymentId) {
        Payment payment = paymentRepository.findOwnedDetails(paymentId, currentUser.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_NOT_FOUND));
        return toResponse(payment);
    }

    @Transactional(readOnly = true)
    public PaymentResponse getOwned(User currentUser, Payment payment) {
        return getOwned(currentUser, payment.getId());
    }

    private PaymentResponse toResponse(Payment payment) {
        Refund refund = refundRepository.findFirstByPayment_IdOrderByCreatedAtDesc(payment.getId())
                .orElse(null);
        return new PaymentResponse(
                payment.getId(),
                payment.getPurpose(),
                payment.getMethod(),
                payment.getStatus(),
                payment.getAmountMinor(),
                payment.getCurrencyCode(),
                payment.getFxQuote() == null ? null : payment.getFxQuote().getId(),
                payment.getChargeAmountMinor(),
                payment.getChargeCurrencyCode(),
                payment.getFxRate(),
                payment.getFxRateSource(),
                payment.getFxQuotedAt(),
                payment.getStatus() == PaymentStatus.REQUIRES_ACTION
                        ? payment.getPaymentPageUrl()
                        : null,
                payment.getExpiresAt(),
                payment.getReservation() == null ? null : payment.getReservation().getId(),
                payment.getReservation() == null ? null : payment.getReservation().getStatus(),
                refund == null ? null : refund.getId(),
                refund == null ? null : refund.getStatus(),
                refund == null ? null : refund.getAmountMinor(),
                refund == null ? null : refund.getChargeAmountMinor(),
                refund == null ? null : refund.getChargeCurrencyCode(),
                payment.getFailureCode(),
                payment.getCreatedAt(),
                payment.getUpdatedAt()
        );
    }
}
