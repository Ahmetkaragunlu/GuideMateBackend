package com.ahmetkaragunlu.guidematebackend.auth.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Getter
@MappedSuperclass
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class AbstractToken extends BaseEntity {

    @Column(nullable = false, unique = true, length = 64)
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "used")
    private boolean used = false;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    protected AbstractToken(String token, LocalDateTime expiresAt) {
        this.token = token;
        this.expiresAt = expiresAt;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    public void markUsed() {
        this.used = true;
        this.usedAt = LocalDateTime.now();
    }
}
