package com.ahmetkaragunlu.guidematebackend.media;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaFileValidator;
import com.ahmetkaragunlu.guidematebackend.media.service.ValidatedMedia;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.util.unit.DataSize;

import java.nio.file.Path;
import java.time.Duration;
import java.util.stream.Stream;

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

    @ParameterizedTest
    @MethodSource("supportedImages")
    void acceptsMatchingImageSignatureAndRemovesPathFromOriginalName(
            String contentType,
            String expectedExtension,
            byte[] signature
    ) {
        MockMultipartFile file = new MockMultipartFile(
                "file",
                "../../profile." + expectedExtension,
                contentType + "; charset=binary",
                signature
        );

        ValidatedMedia result = validator.validate(file);

        assertThat(result.contentType()).isEqualTo(contentType);
        assertThat(result.fileExtension()).isEqualTo(expectedExtension);
        assertThat(result.originalFileName()).isEqualTo("profile." + expectedExtension);
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

    private static Stream<Arguments> supportedImages() {
        return Stream.of(
                Arguments.of("image/png", "png", PNG),
                Arguments.of("image/jpeg", "jpg", new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}),
                Arguments.of(
                        "image/webp",
                        "webp",
                        new byte[]{'R', 'I', 'F', 'F', 0, 0, 0, 0, 'W', 'E', 'B', 'P'}
                )
        );
    }
}
