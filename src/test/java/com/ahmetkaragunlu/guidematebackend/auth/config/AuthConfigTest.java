package com.ahmetkaragunlu.guidematebackend.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AuthConfigTest {

    private final AuthConfig config = new AuthConfig();

    @Test
    void acceptsGoogleIssuerAndConfiguredAudience() {
        Jwt httpsIssuerToken = token("https://accounts.google.com", List.of("client-id"));
        Jwt legacyIssuerToken = token("accounts.google.com", List.of("client-id"));

        assertThat(config.issuerValidator().validate(httpsIssuerToken).hasErrors()).isFalse();
        assertThat(config.issuerValidator().validate(legacyIssuerToken).hasErrors()).isFalse();
        assertThat(config.audienceValidator("client-id").validate(httpsIssuerToken).hasErrors()).isFalse();
    }

    @Test
    void rejectsUnexpectedIssuerOrAudience() {
        OAuth2TokenValidator<Jwt> issuerValidator = config.issuerValidator();
        OAuth2TokenValidator<Jwt> audienceValidator = config.audienceValidator("client-id");

        assertThat(issuerValidator.validate(token("https://example.com", List.of("client-id"))).hasErrors())
                .isTrue();
        assertThat(audienceValidator.validate(
                token("https://accounts.google.com", List.of("another-client"))
        ).hasErrors()).isTrue();
    }

    private Jwt token(String issuer, List<String> audience) {
        Instant issuedAt = Instant.parse("2026-08-27T10:00:00Z");
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .issuer(issuer)
                .audience(audience)
                .subject("google-subject")
                .issuedAt(issuedAt)
                .expiresAt(issuedAt.plusSeconds(300))
                .build();
    }
}
