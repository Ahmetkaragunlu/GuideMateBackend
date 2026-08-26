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

import java.time.LocalDateTime;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "confirmation_tokens", indexes = {
        @Index(name = "idx_ct_token", columnList = "token"),
        @Index(name = "idx_ct_user_id", columnList = "user_id")
})
public class ConfirmationToken extends AbstractToken {

    @Column(name = "confirmed_at")
    private LocalDateTime confirmedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public ConfirmationToken(User user, String token, LocalDateTime createdAt) {
        super(token, createdAt.plusHours(24));
        this.user = user;
    }

    public void confirm(LocalDateTime confirmedAt) {
        this.confirmedAt = confirmedAt;
        markUsed(confirmedAt);
    }

    public boolean isConfirmed() {
        return this.confirmedAt != null;
    }
}
