package com.ahmetkaragunlu.guidematebackend.auth.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Column;
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
@Table(name = "confirmation_tokens", indexes = {
        @Index(name = "idx_ct_token_hash", columnList = "token_hash"),
        @Index(name = "idx_ct_user_id", columnList = "user_id")
})
public class ConfirmationToken extends AbstractToken {

    @Column(name = "confirmed_at")
    private Instant confirmedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public ConfirmationToken(User user, String tokenHash, Instant createdAt) {
        super(tokenHash, createdAt.plus(Duration.ofHours(24)));
        this.user = user;
    }

    public void confirm(Instant confirmedAt) {
        this.confirmedAt = confirmedAt;
        markUsed(confirmedAt);
    }

    public boolean isConfirmed() {
        return this.confirmedAt != null;
    }
}
