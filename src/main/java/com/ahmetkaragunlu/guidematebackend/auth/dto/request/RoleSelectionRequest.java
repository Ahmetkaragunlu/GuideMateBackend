package com.ahmetkaragunlu.guidematebackend.auth.dto.request;

import jakarta.validation.constraints.NotNull;

public record RoleSelectionRequest(
        @NotNull(message = "{validation.role.notNull}")
        SelectableRole role
) {
}
