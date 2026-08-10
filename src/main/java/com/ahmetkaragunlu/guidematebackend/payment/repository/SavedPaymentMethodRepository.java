package com.ahmetkaragunlu.guidematebackend.payment.repository;

import com.ahmetkaragunlu.guidematebackend.payment.domain.SavedPaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.SavedPaymentMethodStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface SavedPaymentMethodRepository extends JpaRepository<SavedPaymentMethod, UUID> {

    List<SavedPaymentMethod> findByUser_IdAndStatusOrderByDefaultMethodDescCreatedAtAsc(
            Long userId,
            SavedPaymentMethodStatus status
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT method FROM SavedPaymentMethod method WHERE method.user.id = :userId")
    List<SavedPaymentMethod> findByUserIdForUpdate(@Param("userId") Long userId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT method FROM SavedPaymentMethod method "
            + "WHERE method.id = :methodId AND method.user.id = :userId")
    Optional<SavedPaymentMethod> findOwnedByIdForUpdate(
            @Param("methodId") UUID methodId,
            @Param("userId") Long userId
    );
}
