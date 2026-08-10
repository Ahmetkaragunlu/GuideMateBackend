package com.ahmetkaragunlu.guidematebackend.common.security;

import com.ahmetkaragunlu.guidematebackend.common.config.DataProtectionProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class SensitiveDataCipher {

    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;

    private final SecretKeySpec encryptionKey;
    private final SecretKeySpec fingerprintKey;
    private final SecureRandom secureRandom = new SecureRandom();

    public SensitiveDataCipher(DataProtectionProperties properties) {
        byte[] keyBytes;
        try {
            keyBytes = Base64.getDecoder().decode(properties.dataProtectionKey());
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException("security.data-protection-key must be valid Base64", exception);
        }
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException("security.data-protection-key must decode to 32 bytes");
        }
        this.encryptionKey = new SecretKeySpec(keyBytes, "AES");
        this.fingerprintKey = new SecretKeySpec(keyBytes, HMAC_ALGORITHM);
    }

    public String encrypt(String value) {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] encrypted = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ByteBuffer.allocate(iv.length + encrypted.length)
                    .put(iv)
                    .put(encrypted)
                    .array());
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Sensitive data encryption failed", exception);
        }
    }

    public String decrypt(String encryptedValue) {
        byte[] payload;
        try {
            payload = Base64.getDecoder().decode(encryptedValue);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("Encrypted value is malformed", exception);
        }
        if (payload.length <= IV_LENGTH) {
            throw new IllegalStateException("Encrypted value is malformed");
        }
        byte[] iv = new byte[IV_LENGTH];
        byte[] encrypted = new byte[payload.length - IV_LENGTH];
        System.arraycopy(payload, 0, iv, 0, IV_LENGTH);
        System.arraycopy(payload, IV_LENGTH, encrypted, 0, encrypted.length);
        try {
            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Sensitive data decryption failed", exception);
        }
    }

    public String fingerprint(String value) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(fingerprintKey);
            return HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("Sensitive data fingerprinting failed", exception);
        }
    }
}
