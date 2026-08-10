package com.ahmetkaragunlu.guidematebackend.wallet.repository;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccount;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccountStatus;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface BankAccountRepository extends JpaRepository<BankAccount, UUID> {

    List<BankAccount> findByGuide_IdAndStatusOrderByDefaultAccountDescCreatedAtAsc(
            Long guideId,
            BankAccountStatus status
    );

    Page<BankAccount> findByGuide_IdAndStatusOrderByDefaultAccountDescCreatedAtAsc(
            Long guideId,
            BankAccountStatus status,
            Pageable pageable
    );

    boolean existsByGuide_IdAndIbanFingerprint(Long guideId, String ibanFingerprint);

    boolean existsByGuide_IdAndStatus(Long guideId, BankAccountStatus status);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT account FROM BankAccount account "
            + "WHERE account.id = :accountId AND account.guide.id = :guideId")
    Optional<BankAccount> findOwnedByIdForUpdate(
            @Param("accountId") UUID accountId,
            @Param("guideId") Long guideId
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT account FROM BankAccount account "
            + "WHERE account.guide.id = :guideId AND account.defaultAccount = true "
            + "AND account.status = :status")
    Optional<BankAccount> findDefaultForUpdate(
            @Param("guideId") Long guideId,
            @Param("status") BankAccountStatus status
    );
}
