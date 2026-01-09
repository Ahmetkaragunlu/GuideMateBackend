package com.ahmetkaragunlu.guidematebackend.auth.dto;

import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import jakarta.validation.constraints.NotNull;

public record RoleSelectionRequest(
        @NotNull(message = "{validation.role.notNull}")
        RoleType role
) {}