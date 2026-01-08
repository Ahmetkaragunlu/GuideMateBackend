package com.ahmetkaragunlu.guidematebackend.auth.domain;


import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
@Table(name = "password_reset_tokens", indexes = {
        @Index(name = "idx_prt_token", columnList = "token"),
        @Index(name = "idx_prt_user_id", columnList = "user_id")
})
public class PasswordResetToken extends AbstractToken {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public PasswordResetToken(User user) {
        super(LocalDateTime.now().plusMinutes(15));
        this.user = user;
    }
}