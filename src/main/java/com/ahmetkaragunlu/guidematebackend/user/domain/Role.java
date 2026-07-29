package com.ahmetkaragunlu.guidematebackend.user.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.BaseEntity;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@ToString(callSuper = true)
@Entity
@Table(name = "roles", indexes = @Index(name = "idx_role_name", columnList = "name"))
public class Role extends BaseEntity {

    @Column(name = "name", nullable = false, unique = true, length = 50)
    private String name;

}
