package com.ahmetkaragunlu.guidematebackend.user.domain;

import com.ahmetkaragunlu.guidematebackend.common.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.Objects;

@Getter
@Setter
@ToString(callSuper = true, exclude = {"role", "password"})
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_account_status", columnList = "account_status")
})
public class User extends BaseEntity implements UserDetails {

    @Column(name = "first_name", nullable = false, length = 100)
    private String firstName;

    @Column(name = "last_name", nullable = false, length = 100)
    private String lastName;

    @Column(name = "email", nullable = false, unique = true, length = 320)
    private String email;

    @Column(name = "password", nullable = false, length = 100)
    private String password;

    @Column(name = "google_subject", unique = true, length = 255)
    private String googleSubject;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id")
    private Role role;

    @Column(name = "role_selected")
    private boolean roleSelected = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "account_status", nullable = false, length = 32)
    private AccountStatus accountStatus = AccountStatus.PENDING_VERIFICATION;

    @Column(name = "token_version", nullable = false)
    private int tokenVersion;

    public void activate() {
        this.accountStatus = AccountStatus.ACTIVE;
    }

    public void incrementTokenVersion() {
        this.tokenVersion++;
    }

    public boolean hasRole(RoleType expectedRole) {
        return expectedRole != null
                && role != null
                && expectedRole.name().equals(role.getName());
    }

    public String displayName() {
        return (firstName + " " + lastName).trim();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (role != null && role.getName() != null) {
            return Collections.singletonList(
                    new SimpleGrantedAuthority(role.getName())
            );
        }
        return Collections.emptyList();
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return accountStatus == AccountStatus.ACTIVE;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(email, user.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(email);
    }
}
