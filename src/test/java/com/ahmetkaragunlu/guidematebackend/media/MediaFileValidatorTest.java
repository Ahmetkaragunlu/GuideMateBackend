package com.ahmetkaragunlu.guidematebackend.media;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaFileValidator;
import com.ahmetkaragunlu.guidematebackend.media.service.ValidatedMedia;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.util.unit.DataSize;

import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MediaFileValidatorTest {

    private static final byte[] PNG = {
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    };

    private MediaFileValidator validator;

    @BeforeEach
    void setUp() {
        validator = new MediaFileValidator(new MediaProperties(
                Path.of("/tmp/guidemate-media-validator-test"),
                DataSize.ofKilobytes(10),
                Duration.ofHours(1)
        ));
    }

    @Test
    void acceptsMatchingImageSignatureAndRemovesPathFromOriginalName() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "../../profile.png",
                "image/png; charset=binary",
                PNG
        );

        ValidatedMedia result = validator.validate(file);

        assertThat(result.contentType()).isEqualTo("image/png");
        assertThat(result.fileExtension()).isEqualTo("png");
        assertThat(result.originalFileName()).isEqualTo("profile.png");
    }

    @Test
    void rejectsDeclaredImageWhenBinarySignatureDoesNotMatch() {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "not-an-image.png",
                "image/png",
                "plain text".getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );

        assertThatThrownBy(() -> validator.validate(file))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.MEDIA_INVALID_TYPE));
    }

    @Test
    void rejectsFileAboveConfiguredLimit() {
        byte[] oversized = new byte[10 * 1024 + 1];
        System.arraycopy(PNG, 0, oversized, 0, PNG.length);
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "large.png",
                "image/png",
                oversized
        );

        assertThatThrownBy(() -> validator.validate(file))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.MEDIA_TOO_LARGE));
    }
}
