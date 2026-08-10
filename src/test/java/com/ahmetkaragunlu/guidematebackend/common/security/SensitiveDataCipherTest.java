package com.ahmetkaragunlu.guidematebackend.common.security;

import com.ahmetkaragunlu.guidematebackend.common.config.DataProtectionProperties;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SensitiveDataCipherTest {

    private final SensitiveDataCipher cipher = new SensitiveDataCipher(
            new DataProtectionProperties(Base64.getEncoder().encodeToString(new byte[32]))
    );

    @Test
    void encryptsWithRandomIvAndDecryptsOriginalValue() {
        String value = "TR250006400000000000000001";

        String first = cipher.encrypt(value);
        String second = cipher.encrypt(value);

        assertThat(first).isNotEqualTo(second).doesNotContain(value);
        assertThat(cipher.decrypt(first)).isEqualTo(value);
        assertThat(cipher.fingerprint(value)).isEqualTo(cipher.fingerprint(value));
    }

    @Test
    void rejectsTamperedCiphertext() {
        byte[] payload = Base64.getDecoder().decode(cipher.encrypt("provider-token"));
        payload[payload.length - 1] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(payload);

        assertThatThrownBy(() -> cipher.decrypt(tampered))
                .isInstanceOf(IllegalStateException.class);
    }
}
