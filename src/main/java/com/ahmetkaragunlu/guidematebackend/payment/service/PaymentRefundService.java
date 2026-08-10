package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.domain.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletAccountService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentRefundService {

    private static final List<RefundStatus> RESERVED_REFUND_STATUSES = List.of(
            RefundStatus.REQUESTED,
            RefundStatus.PROCESSING,
            RefundStatus.SUCCEEDED,
            RefundStatus.MANUAL_REVIEW
    );

    private final PaymentRepository paymentRepository;
    private final RefundRepository refundRepository;
    private final UserRepository userRepository;
    private final WalletAccountService walletAccountService;
    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

    @Transactional
    public Refund requestFullRefundForReservation(
            UUID reservationId,
            User requestedBy,
            String idempotencyKey
    ) {
        Payment payment = paymentRepository.findByReservationIdAndStatusForUpdate(
                reservationId,
                PaymentStatus.SUCCEEDED
        ).orElse(null);
        if (payment == null) {
            return null;
        }
        return requestFullRefund(payment, requestedBy, idempotencyKey);
    }

    @Transactional
    public Refund requestFullRefund(UUID paymentId, User requestedBy, String idempotencyKey) {
        Payment payment = paymentRepository.findByIdForUpdate(paymentId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PAYMENT_NOT_FOUND));
        return requestFullRefund(payment, requestedBy, idempotencyKey);
    }

    @Transactional(readOnly = true)
    public Refund findLatestForReservation(UUID reservationId) {
        return refundRepository.findFirstByPayment_Reservation_IdOrderByCreatedAtDesc(reservationId)
                .orElse(null);
    }

    private Refund requestFullRefund(Payment payment, User requestedBy, String idempotencyKey) {
        if (payment.getStatus() != PaymentStatus.SUCCEEDED) {
            throw new BusinessException(ErrorCode.REFUND_FAILED);
        }
        Refund previous = refundRepository.findByPayment_IdAndIdempotencyKey(
                payment.getId(),
                idempotencyKey
        ).orElse(null);
        if (previous != null) {
            return previous;
        }
        long alreadyReserved = refundRepository.sumAmountByPaymentAndStatuses(
                payment.getId(),
                RESERVED_REFUND_STATUSES
        );
        long refundableAmount = payment.getAmountMinor() - alreadyReserved;
        if (refundableAmount <= 0) {
            return refundRepository.findFirstByPayment_IdOrderByCreatedAtDesc(payment.getId())
                    .orElseThrow(() -> new BusinessException(ErrorCode.REFUND_AMOUNT_EXCEEDED));
        }

        Instant now = clock.instant();
        User requesterReference = userRepository.getReferenceById(requestedBy.getId());
        if (payment.getMethod() == PaymentMethod.WALLET) {
            Refund refund = refundRepository.saveAndFlush(Refund.succeededWallet(
                    payment,
                    requesterReference,
                    refundableAmount,
                    idempotencyKey,
                    now
            ));
            Wallet wallet = walletAccountService.getOrCreateForUpdate(payment.getUser());
            walletAccountService.credit(
                    wallet,
                    refundableAmount,
                    LedgerEntryType.REFUND,
                    "REFUND",
                    refund.getId(),
                    "refund-credit:" + refund.getId(),
                    now
            );
            return refund;
        }

        Refund refund = refundRepository.saveAndFlush(Refund.requested(
                payment,
                requesterReference,
                refundableAmount,
                idempotencyKey,
                now
        ));
        if (payment.getProviderTransactionId() == null || payment.getProviderTransactionId().isBlank()) {
            refund.requireManualReview("PROVIDER_REFERENCE_MISSING");
            return refund;
        }
        eventPublisher.publishEvent(new RefundRequestedEvent(refund.getId()));
        return refund;
    }
}
