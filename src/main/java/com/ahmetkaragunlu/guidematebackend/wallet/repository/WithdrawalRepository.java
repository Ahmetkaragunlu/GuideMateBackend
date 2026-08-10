package com.ahmetkaragunlu.guidematebackend.wallet.repository;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.Withdrawal;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WithdrawalStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.Optional;
import java.util.UUID;

public interface WithdrawalRepository extends JpaRepository<Withdrawal, UUID> {

    @EntityGraph(attributePaths = {"bankAccount", "wallet"})
    Optional<Withdrawal> findByWallet_IdAndIdempotencyKey(UUID walletId, String idempotencyKey);

    @EntityGraph(attributePaths = {"bankAccount", "wallet"})
    Page<Withdrawal> findByWallet_User_IdOrderByRequestedAtDesc(Long userId, Pageable pageable);

    @Query("SELECT COALESCE(SUM(withdrawal.amountMinor), 0) FROM Withdrawal withdrawal "
            + "WHERE withdrawal.wallet.id = :walletId AND withdrawal.status IN :statuses")
    long reservedAmount(
            @Param("walletId") UUID walletId,
            @Param("statuses") Collection<WithdrawalStatus> statuses
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT withdrawal FROM Withdrawal withdrawal WHERE withdrawal.id = :withdrawalId")
    Optional<Withdrawal> findByIdForUpdate(@Param("withdrawalId") UUID withdrawalId);
}
