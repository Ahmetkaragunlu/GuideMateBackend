package com.ahmetkaragunlu.guidematebackend.auth.service.email;


public interface EmailService {
    void sendConfirmationEmail(String to, String token);
    void sendPasswordResetEmail(String to, String token);
}
