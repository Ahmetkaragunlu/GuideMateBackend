package com.ahmetkaragunlu.guidematebackend.user.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.BaseEntity;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@ToString(callSuper = true, exclude = "users")
@Entity
@Table(name = "roles", indexes = @Index(name = "idx_role_name", columnList = "name"))
public class Role extends BaseEntity {

    @Column(name = "name", nullable = false, unique = true)
    private String name;

    @OneToMany(mappedBy = "role")
    private Set<User> users = new HashSet<>();

    public Role(String name) {
        this.name = name;
    }
}