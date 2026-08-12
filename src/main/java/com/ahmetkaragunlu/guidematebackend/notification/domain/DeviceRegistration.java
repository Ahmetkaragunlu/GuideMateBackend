package com.ahmetkaragunlu.guidematebackend.notification.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.UuidAuditedEntity;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Getter
@Entity
@Table(
        name = "device_registrations",
        indexes = {
                @Index(name = "idx_device_registration_user_active", columnList = "user_id, active"),
                @Index(name = "idx_device_registration_cleanup", columnList = "active, last_seen_at")
        },
        uniqueConstraints = {
                @UniqueConstraint(name = "uq_device_registration_installation", columnNames = "installation_id"),
                @UniqueConstraint(
                        name = "uq_device_registration_firebase_installation",
                        columnNames = "firebase_installation_id"
                )
        }
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class DeviceRegistration extends UuidAuditedEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "installation_id", nullable = false)
    private UUID installationId;

    @Column(name = "firebase_installation_id", nullable = false, length = 128)
    private String firebaseInstallationId;

    @Enumerated(EnumType.STRING)
    @Column(name = "platform", nullable = false, length = 16)
    private DevicePlatform platform;

    @Column(name = "active", nullable = false)
    private boolean active;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    public DeviceRegistration(User user, UUID installationId, String firebaseInstallationId, Instant now) {
        register(user, installationId, firebaseInstallationId, now);
        this.platform = DevicePlatform.ANDROID;
    }

    public void register(User user, UUID installationId, String firebaseInstallationId, Instant now) {
        this.user = Objects.requireNonNull(user);
        this.installationId = Objects.requireNonNull(installationId);
        this.firebaseInstallationId = Objects.requireNonNull(firebaseInstallationId);
        this.platform = DevicePlatform.ANDROID;
        this.active = true;
        this.lastSeenAt = Objects.requireNonNull(now);
    }

    public void deactivate() {
        active = false;
    }
}
