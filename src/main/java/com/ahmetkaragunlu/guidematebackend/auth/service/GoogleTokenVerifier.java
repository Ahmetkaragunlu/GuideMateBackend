package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

@Component
public class GoogleTokenVerifier {

    private final JwtDecoder decoder;

    public GoogleTokenVerifier(@Qualifier("googleJwtDecoder") JwtDecoder decoder) {
        this.decoder = decoder;
    }

    public GoogleIdentity verify(String rawIdToken) {
        try {
            Jwt token = decoder.decode(rawIdToken);
            String subject = token.getSubject();
            String email = token.getClaimAsString("email");
            if (!Boolean.TRUE.equals(token.getClaim("email_verified"))
                    || subject == null
                    || subject.isBlank()
                    || email == null
                    || email.isBlank()) {
                throw new BusinessException(ErrorCode.GOOGLE_LOGIN_FAILED);
            }

            return new GoogleIdentity(subject, email);
        } catch (JwtException | IllegalArgumentException exception) {
            throw new BusinessException(ErrorCode.GOOGLE_LOGIN_FAILED, exception);
        }
    }

    public record GoogleIdentity(String subject, String email) {
    }
}
