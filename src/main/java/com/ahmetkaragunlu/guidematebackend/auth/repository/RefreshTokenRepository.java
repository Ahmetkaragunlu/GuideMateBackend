package com.ahmetkaragunlu.guidematebackend.auth.repository;

import com.ahmetkaragunlu.guidematebackend.auth.domain.RefreshToken;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
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
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT token
              FROM RefreshToken token
              JOIN FETCH token.user user
             WHERE token.tokenHash = :tokenHash
            """)
    Optional<RefreshToken> findByTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    @Modifying
    @Query("""
            UPDATE RefreshToken token
               SET token.revokedAt = :now
             WHERE token.user = :user
               AND token.installationId = :installationId
               AND token.revokedAt IS NULL
            """)
    void revokeActiveForInstallation(
            @Param("user") User user,
            @Param("installationId") String installationId,
            @Param("now") Instant now
    );

    @Modifying
    @Query("""
            UPDATE RefreshToken token
               SET token.revokedAt = :now
             WHERE token.familyId = :familyId
               AND token.revokedAt IS NULL
            """)
    void revokeActiveFamily(@Param("familyId") String familyId, @Param("now") Instant now);

    @Modifying
    @Query("""
            UPDATE RefreshToken token
               SET token.revokedAt = :now
             WHERE token.user = :user
               AND token.revokedAt IS NULL
            """)
    void revokeAllActiveByUser(@Param("user") User user, @Param("now") Instant now);

    void deleteByExpiresAtBefore(Instant now);
}
