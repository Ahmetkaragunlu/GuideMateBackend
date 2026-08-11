package com.ahmetkaragunlu.guidematebackend.notification.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.UUID;

public record RegisterDeviceRegistrationRequest(
        @NotNull(message = "{validation.installationId.notNull}")
        UUID installationId,

        @NotBlank(message = "{validation.firebaseInstallationId.notBlank}")
        @Size(max = 128, message = "{validation.firebaseInstallationId.size}")
        String firebaseInstallationId
) {
}
