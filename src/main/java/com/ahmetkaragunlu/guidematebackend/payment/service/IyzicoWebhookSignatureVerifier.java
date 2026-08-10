package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.dto.IyzicoWebhookRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;

@Component
@RequiredArgsConstructor
public class IyzicoWebhookSignatureVerifier {

    private static final String HMAC_SHA_256 = "HmacSHA256";

    private final PaymentProperties properties;

    public boolean isValid(String signature, IyzicoWebhookRequest request) {
        if (signature == null || signature.isBlank() || request == null) {
            return false;
        }
        try {
            byte[] expected = calculate(request);
            byte[] actual = HexFormat.of().parseHex(signature.trim());
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException | GeneralSecurityException exception) {
            return false;
        }
    }

    private byte[] calculate(IyzicoWebhookRequest request) throws GeneralSecurityException {
        String secretKey = properties.iyzico().secretKey();
        Mac mac = Mac.getInstance(HMAC_SHA_256);
        mac.init(new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), HMAC_SHA_256));
        String payload = secretKey
                + request.value(request.eventType())
                + request.value(request.paymentId())
                + request.value(request.token())
                + request.value(request.conversationId())
                + request.value(request.status());
        return mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
    }
}
