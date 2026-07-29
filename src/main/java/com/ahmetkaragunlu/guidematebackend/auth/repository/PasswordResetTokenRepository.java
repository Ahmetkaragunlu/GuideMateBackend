package com.ahmetkaragunlu.guidematebackend.auth.repository;



import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    @Modifying
    @Query("""
            UPDATE PasswordResetToken token
               SET token.used = true, token.usedAt = :now
             WHERE token.user.id = :userId
               AND token.used = false
               AND token.expiresAt > :now
            """)
    void invalidateActiveTokens(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    Optional<PasswordResetToken> findByToken(String token);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT token FROM PasswordResetToken token WHERE token.token = :token")
    Optional<PasswordResetToken> findByTokenForUpdate(@Param("token") String token);

    void deleteByExpiresAtBefore(LocalDateTime now);
}
