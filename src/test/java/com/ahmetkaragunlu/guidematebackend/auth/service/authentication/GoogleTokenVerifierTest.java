package com.ahmetkaragunlu.guidematebackend.auth.service.authentication;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GoogleTokenVerifierTest {

    private final JwtDecoder decoder = mock(JwtDecoder.class);
    private final GoogleTokenVerifier verifier = new GoogleTokenVerifier(decoder);

    @Test
    void returnsVerifiedGoogleIdentity() {
        when(decoder.decode("valid-token")).thenReturn(token(true, "subject-1", "tourist@example.com"));

        GoogleTokenVerifier.GoogleIdentity identity = verifier.verify("valid-token");

        assertThat(identity.subject()).isEqualTo("subject-1");
        assertThat(identity.email()).isEqualTo("tourist@example.com");
    }

    @Test
    void rejectsUnverifiedOrIncompleteIdentity() {
        when(decoder.decode("unverified-token")).thenReturn(token(false, "subject-1", "tourist@example.com"));

        assertGoogleLoginFailure("unverified-token");
    }

    @Test
    void mapsDecoderFailureToStableGoogleLoginError() {
        when(decoder.decode("invalid-token")).thenThrow(new JwtException("invalid"));

        assertGoogleLoginFailure("invalid-token");
    }

    private Jwt token(boolean emailVerified, String subject, String email) {
        Instant issuedAt = Instant.parse("2026-08-27T10:00:00Z");
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject(subject)
                .claim("email", email)
                .claim("email_verified", emailVerified)
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(300))
                .build();
    }

    private void assertGoogleLoginFailure(String token) {
        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.GOOGLE_LOGIN_FAILED));
    }
}
