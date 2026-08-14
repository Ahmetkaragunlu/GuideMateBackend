package com.ahmetkaragunlu.guidematebackend.payment.repository;

import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PaymentRepository extends JpaRepository<Payment, UUID> {

    Optional<Payment> findByUser_IdAndPurposeAndIdempotencyKey(
            Long userId,
            PaymentPurpose purpose,
            String idempotencyKey
    );

    @Query("SELECT payment FROM Payment payment "
            + "LEFT JOIN FETCH payment.reservation reservation "
            + "LEFT JOIN FETCH reservation.session session "
            + "WHERE payment.id = :paymentId AND payment.user.id = :userId")
    Optional<Payment> findOwnedDetails(
            @Param("paymentId") UUID paymentId,
            @Param("userId") Long userId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT payment FROM Payment payment WHERE payment.id = :paymentId")
    Optional<Payment> findByIdForUpdate(@Param("paymentId") UUID paymentId);

    Optional<Payment> findByProviderTokenFingerprint(String providerTokenFingerprint);

    Optional<Payment> findByFxQuote_Id(UUID quoteId);

    @EntityGraph(attributePaths = "reservation")
    List<Payment> findAllByIdIn(Collection<UUID> ids);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT payment FROM Payment payment "
            + "LEFT JOIN FETCH payment.reservation reservation "
            + "WHERE reservation.id = :reservationId AND payment.status = :status")
    Optional<Payment> findByReservationIdAndStatusForUpdate(
            @Param("reservationId") UUID reservationId,
            @Param("status") PaymentStatus status
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT payment FROM Payment payment "
            + "WHERE payment.reservation.id = :reservationId AND payment.status IN :statuses")
    List<Payment> findByReservationIdAndStatusesForUpdate(
            @Param("reservationId") UUID reservationId,
            @Param("statuses") Collection<PaymentStatus> statuses
    );

    @Query("""
            SELECT payment.id FROM Payment payment
            WHERE payment.method = :method
              AND payment.providerTokenEncrypted IS NOT NULL
              AND payment.status IN :statuses
              AND payment.expiresAt <= :now
              AND payment.reconciliationAttemptCount < :maxAttempts
              AND (
                  payment.lastReconciliationAt IS NULL
                  OR payment.lastReconciliationAt <= :retryBefore
              )
            ORDER BY payment.expiresAt, payment.id
            """)
    List<UUID> findReconciliationCandidateIds(
            @Param("method") PaymentMethod method,
            @Param("statuses") Collection<PaymentStatus> statuses,
            @Param("now") Instant now,
            @Param("retryBefore") Instant retryBefore,
            @Param("maxAttempts") int maxAttempts,
            Pageable pageable
    );
}
