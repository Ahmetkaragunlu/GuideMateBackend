package com.ahmetkaragunlu.guidematebackend.user.domain;


import com.ahmetkaragunlu.guidematebackend.auth.domain.ConfirmationToken;
import com.ahmetkaragunlu.guidematebackend.auth.domain.PasswordResetToken;
import com.ahmetkaragunlu.guidematebackend.common.domain.BaseEntity;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Getter
@Setter
@ToString(callSuper = true, exclude = {"role", "confirmationTokens", "password"})
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email"),
        @Index(name = "idx_user_active", columnList = "active")
})
public class User extends BaseEntity implements UserDetails {

    @NotBlank(message = "{validation.user.firstName.notBlank}")
    @Column(name = "first_name", nullable = false)
    private String firstName;

    @NotBlank(message = "{validation.user.lastName.notBlank}")
    @Column(name = "last_name", nullable = false)
    private String lastName;

    @NotBlank(message = "{validation.user.email.notBlank}")
    @Email(message = "{validation.user.email.invalid}")
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "password")
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider")
    private AuthProvider authProvider;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id")
    private Role role;

    @Column(name = "role_selected")
    private boolean roleSelected = false;

    @Column(name = "active")
    private boolean active = false;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ConfirmationToken> confirmationTokens = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    private List<PasswordResetToken> passwordResetTokens = new ArrayList<>();

    public void addPasswordResetToken(PasswordResetToken token) {
        this.passwordResetTokens.add(token);
        token.setUser(this);
    }

    public void addConfirmationToken(ConfirmationToken token) {
        this.confirmationTokens.add(token);
        token.setUser(this);
    }

    // ==================== UserDetails Implementation ====================
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
        return active;
    }

    // ==================== Equals & HashCode ====================

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

    // ==================== Lifecycle Callbacks ====================

    @PrePersist
    @PreUpdate
    public void prepareData() {
        if (this.email != null) {
            this.email = this.email.toLowerCase().trim();
        }
    }
}