package com.ahmetkaragunlu.guidematebackend.auth.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Duration;
import java.time.Instant;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "password_reset_tokens", indexes = {
        @Index(name = "idx_prt_token_hash", columnList = "token_hash"),
        @Index(name = "idx_prt_user_id", columnList = "user_id")
})
public class PasswordResetToken extends AbstractToken {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public PasswordResetToken(User user, String tokenHash, Instant createdAt) {
        super(tokenHash, createdAt.plus(Duration.ofMinutes(15)));
        this.user = user;
    }
}
