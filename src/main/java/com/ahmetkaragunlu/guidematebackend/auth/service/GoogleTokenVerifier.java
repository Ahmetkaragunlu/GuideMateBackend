package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

@Component
public class GoogleTokenVerifier {

    private final GoogleIdTokenVerifier verifier;

    public GoogleTokenVerifier(@Value("${google.client-id}") String googleClientId) {
        this.verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), new GsonFactory())
                .setAudience(Collections.singletonList(googleClientId))
                .build();
    }

    public GoogleIdentity verify(String rawIdToken) {
        try {
            GoogleIdToken idToken = verifier.verify(rawIdToken);
            if (idToken == null) {
                throw new BusinessException(ErrorCode.GOOGLE_LOGIN_FAILED);
            }

            GoogleIdToken.Payload payload = idToken.getPayload();
            if (!Boolean.TRUE.equals(payload.getEmailVerified())
                    || payload.getSubject() == null
                    || payload.getSubject().isBlank()
                    || payload.getEmail() == null
                    || payload.getEmail().isBlank()) {
                throw new BusinessException(ErrorCode.GOOGLE_LOGIN_FAILED);
            }

            return new GoogleIdentity(payload.getSubject(), payload.getEmail());
        } catch (GeneralSecurityException | IOException exception) {
            throw new BusinessException(ErrorCode.GOOGLE_LOGIN_FAILED, exception);
        }
    }

    public record GoogleIdentity(String subject, String email) {
    }
}
