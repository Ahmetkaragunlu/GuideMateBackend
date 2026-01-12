package com.ahmetkaragunlu.guidematebackend.auth.repository;



import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    @Modifying
    @Query("UPDATE PasswordResetToken p SET p.expiresAt = :now " +
            "WHERE p.user.id = :userId AND p.used = false AND p.expiresAt > :now")
    void expireActiveTokens(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    @Query("SELECT p FROM PasswordResetToken p " +
            "WHERE p.token = :token " +
            "AND p.used = false " +
            "AND p.expiresAt > :now")
    Optional<PasswordResetToken> findValidToken(@Param("token") String token,
                                                @Param("now") LocalDateTime now);

    void deleteByExpiresAtBefore(LocalDateTime now);
}