package com.ahmetkaragunlu.guidematebackend.auth.repository;


import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface ConfirmationTokenRepository extends JpaRepository<ConfirmationToken, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT token FROM ConfirmationToken token WHERE token.tokenHash = :tokenHash")
    Optional<ConfirmationToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    @Modifying
    @Query("""
            UPDATE ConfirmationToken token
               SET token.used = true, token.usedAt = :now
             WHERE token.user.id = :userId
               AND token.used = false
               AND token.expiresAt > :now
            """)
    void invalidateActiveTokens(@Param("userId") Long userId, @Param("now") Instant now);

    void deleteByExpiresAtBefore(Instant now);
}
