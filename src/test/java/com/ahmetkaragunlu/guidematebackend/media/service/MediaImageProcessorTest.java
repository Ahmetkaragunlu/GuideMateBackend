package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaImageProcessor;
import com.ahmetkaragunlu.guidematebackend.media.service.ProcessedMedia;
import com.ahmetkaragunlu.guidematebackend.media.service.ValidatedMedia;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.util.unit.DataSize;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MediaImageProcessorTest {

    @ParameterizedTest
    @MethodSource("supportedImages")
    void decodesSupportedFormatsAndStoresCleanImage(
            String inputContentType,
            byte[] input,
            String expectedContentType,
            String expectedExtension
    ) throws Exception {
        MediaImageProcessor processor = processor(4096, 4096, 16_777_216);
        ValidatedMedia validated = metadata(inputContentType, input.length);

        ProcessedMedia result = processor.process(file(inputContentType, input), validated);

        assertThat(result.metadata().contentType()).isEqualTo(expectedContentType);
        assertThat(result.metadata().fileExtension()).isEqualTo(expectedExtension);
        assertThat(result.metadata().originalFileName()).endsWith("." + expectedExtension);
        assertThat(result.metadata().sizeBytes()).isEqualTo(result.content().length);
        assertThat(ImageIO.read(new ByteArrayInputStream(result.content()))).isNotNull();
    }

    @Test
    void rejectsContentThatHasAnImageSignatureButCannotBeDecoded() {
        MediaImageProcessor processor = processor(4096, 4096, 16_777_216);
        byte[] corruptPng = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

        assertThatThrownBy(() -> processor.process(
                file("image/png", corruptPng),
                metadata("image/png", corruptPng.length)
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.MEDIA_INVALID_TYPE));
    }

    @Test
    void rejectsImageAboveConfiguredDimensionLimitBeforeStorage() throws Exception {
        MediaImageProcessor processor = processor(2, 2, 4);
        byte[] image = image("png", 3, 2);

        assertThatThrownBy(() -> processor.process(
                file("image/png", image),
                metadata("image/png", image.length)
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.MEDIA_TOO_LARGE));
    }

    @Test
    void removesExifMetadataAndAppendedContentByReencoding() throws Exception {
        MediaImageProcessor processor = processor(4096, 4096, 16_777_216);
        byte[] jpeg = image("jpeg", 2, 2);
        byte[] secret = "Exif\0\0GUIDEMATE-SECRET".getBytes(StandardCharsets.ISO_8859_1);
        byte[] withMetadataAndTail = jpegWithAppSegmentAndTail(jpeg, secret);

        ProcessedMedia result = processor.process(
                file("image/jpeg", withMetadataAndTail),
                metadata("image/jpeg", withMetadataAndTail.length)
        );

        assertThat(new String(result.content(), StandardCharsets.ISO_8859_1))
                .doesNotContain("GUIDEMATE-SECRET")
                .doesNotContain("APPENDED-CONTENT");
        assertThat(ImageIO.read(new ByteArrayInputStream(result.content()))).isNotNull();
    }

    private static Stream<Arguments> supportedImages() throws Exception {
        return Stream.of(
                Arguments.of("image/jpeg", image("jpeg", 2, 2), "image/jpeg", "jpg"),
                Arguments.of("image/png", image("png", 2, 2), "image/png", "png"),
                Arguments.of(
                        "image/webp",
                        new ClassPathResource("media/valid.webp").getContentAsByteArray(),
                        "image/png",
                        "png"
                )
        );
    }

    private MediaImageProcessor processor(int maxWidth, int maxHeight, long maxPixels) {
        return new MediaImageProcessor(new MediaProperties(
                Path.of("build/test-media"),
                DataSize.ofMegabytes(5),
                Duration.ofHours(1),
                maxWidth,
                maxHeight,
                maxPixels
        ));
    }

    private ValidatedMedia metadata(String contentType, long size) {
        String extension = contentType.equals("image/jpeg") ? "jpg" : contentType.substring("image/".length());
        return new ValidatedMedia(contentType, extension, "upload." + extension, size);
    }

    private MockMultipartFile file(String contentType, byte[] content) {
        return new MockMultipartFile("file", "upload", contentType, content);
    }

    private static byte[] image(String format, int width, int height) throws Exception {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        image.setRGB(0, 0, Color.BLUE.getRGB());
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        assertThat(ImageIO.write(image, format, output)).isTrue();
        return output.toByteArray();
    }

    private byte[] jpegWithAppSegmentAndTail(byte[] jpeg, byte[] appPayload) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.writeBytes(new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE1});
        int segmentLength = appPayload.length + 2;
        output.write((segmentLength >>> 8) & 0xFF);
        output.write(segmentLength & 0xFF);
        output.writeBytes(appPayload);
        output.writeBytes(java.util.Arrays.copyOfRange(jpeg, 2, jpeg.length));
        output.writeBytes("APPENDED-CONTENT".getBytes(StandardCharsets.ISO_8859_1));
        return output.toByteArray();
    }
}
