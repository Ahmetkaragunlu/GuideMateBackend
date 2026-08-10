package com.ahmetkaragunlu.guidematebackend.wallet.repository;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerDirection;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WalletLedgerEntry;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface WalletLedgerRepository extends JpaRepository<WalletLedgerEntry, UUID> {

    @Query("SELECT COALESCE(SUM(CASE WHEN entry.direction = :credit THEN entry.amountMinor "
            + "ELSE -entry.amountMinor END), 0) FROM WalletLedgerEntry entry "
            + "WHERE entry.wallet.id = :walletId")
    long balance(
            @Param("walletId") UUID walletId,
            @Param("credit") LedgerDirection credit
    );

    @EntityGraph(attributePaths = "wallet")
    Page<WalletLedgerEntry> findByWallet_IdOrderByOccurredAtDesc(UUID walletId, Pageable pageable);

    Optional<WalletLedgerEntry> findByWallet_IdAndIdempotencyKey(UUID walletId, String idempotencyKey);
}
