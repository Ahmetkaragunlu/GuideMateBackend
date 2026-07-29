package com.ahmetkaragunlu.guidematebackend.auth.dto;

import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;

public enum SelectableRole {
    ROLE_TOURIST(RoleType.ROLE_TOURIST),
    ROLE_GUIDE(RoleType.ROLE_GUIDE);

    private final RoleType internalRole;

    SelectableRole(RoleType internalRole) {
        this.internalRole = internalRole;
    }

    public RoleType toInternalRole() {
        return internalRole;
    }
}
