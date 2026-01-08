package com.ahmetkaragunlu.guidematebackend.auth.domain;




import com.ahmetkaragunlu.guidematebackend.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@MappedSuperclass
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class AbstractToken extends BaseEntity {

    @Column(nullable = false, unique = true)
    private String token;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "used")
    private boolean used = false;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    protected AbstractToken(LocalDateTime expiresAt) {
        this.token = UUID.randomUUID().toString();
        this.expiresAt = expiresAt;
    }

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }
}