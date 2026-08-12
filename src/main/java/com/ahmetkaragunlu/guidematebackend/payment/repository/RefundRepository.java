package com.ahmetkaragunlu.guidematebackend.payment.repository;

import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.domain.RefundStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefundRepository extends JpaRepository<Refund, UUID> {

    Optional<Refund> findByPayment_IdAndIdempotencyKey(UUID paymentId, String idempotencyKey);

    Optional<Refund> findFirstByPayment_IdOrderByCreatedAtDesc(UUID paymentId);

    Optional<Refund> findFirstByPayment_Reservation_IdOrderByCreatedAtDesc(UUID reservationId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT refund FROM Refund refund WHERE refund.id = :refundId")
    Optional<Refund> findByIdForUpdate(@Param("refundId") UUID refundId);

    @Query("SELECT COALESCE(SUM(refund.amountMinor), 0) FROM Refund refund "
            + "WHERE refund.payment.id = :paymentId AND refund.status IN :statuses")
    long sumAmountByPaymentAndStatuses(
            @Param("paymentId") UUID paymentId,
            @Param("statuses") Collection<RefundStatus> statuses
    );

    @Query("SELECT COALESCE(SUM(refund.chargeAmountMinor), 0) FROM Refund refund "
            + "WHERE refund.payment.id = :paymentId AND refund.status IN :statuses")
    long sumChargeAmountByPaymentAndStatuses(
            @Param("paymentId") UUID paymentId,
            @Param("statuses") Collection<RefundStatus> statuses
    );

    @Query("""
            SELECT refund.id FROM Refund refund
            WHERE refund.status IN :statuses
              AND refund.processingAttemptCount < :maxAttempts
              AND (
                  refund.lastProcessingAttemptAt IS NULL
                  OR refund.lastProcessingAttemptAt <= :retryBefore
              )
            ORDER BY refund.requestedAt, refund.id
            """)
    List<UUID> findRetryCandidateIds(
            @Param("statuses") Collection<RefundStatus> statuses,
            @Param("retryBefore") Instant retryBefore,
            @Param("maxAttempts") int maxAttempts,
            Pageable pageable
    );

    @Query("""
            SELECT refund.id FROM Refund refund
            WHERE refund.status = :status
              AND refund.lastProcessingAttemptAt <= :staleBefore
            ORDER BY refund.lastProcessingAttemptAt, refund.id
            """)
    List<UUID> findStaleProcessingIds(
            @Param("status") RefundStatus status,
            @Param("staleBefore") Instant staleBefore,
            Pageable pageable
    );
}
