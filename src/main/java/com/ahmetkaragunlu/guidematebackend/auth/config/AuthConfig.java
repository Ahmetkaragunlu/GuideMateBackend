package com.ahmetkaragunlu.guidematebackend.auth.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestTemplate;

import java.util.Set;

@Configuration
@EnableConfigurationProperties({AuthRateLimitProperties.class, GoogleAuthProperties.class})
public class AuthConfig {

    private static final String GOOGLE_JWK_SET_URI = "https://www.googleapis.com/oauth2/v3/certs";
    private static final Set<String> GOOGLE_ISSUERS = Set.of(
            "accounts.google.com",
            "https://accounts.google.com"
    );
    private static final OAuth2Error INVALID_GOOGLE_TOKEN = new OAuth2Error("invalid_token");

    @Bean("googleJwtDecoder")
    JwtDecoder googleJwtDecoder(GoogleAuthProperties properties) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(properties.connectTimeout());
        requestFactory.setReadTimeout(properties.readTimeout());

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(GOOGLE_JWK_SET_URI)
                .restOperations(new RestTemplate(requestFactory))
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefault(),
                issuerValidator(),
                audienceValidator(properties.clientId())
        ));
        return decoder;
    }

    OAuth2TokenValidator<Jwt> issuerValidator() {
        return token -> {
            String issuer = token.getClaimAsString("iss");
            boolean valid = GOOGLE_ISSUERS.contains(issuer);
            return valid ? OAuth2TokenValidatorResult.success()
                    : OAuth2TokenValidatorResult.failure(INVALID_GOOGLE_TOKEN);
        };
    }

    OAuth2TokenValidator<Jwt> audienceValidator(String clientId) {
        return token -> token.getAudience().contains(clientId)
                ? OAuth2TokenValidatorResult.success()
                : OAuth2TokenValidatorResult.failure(INVALID_GOOGLE_TOKEN);
    }
}
