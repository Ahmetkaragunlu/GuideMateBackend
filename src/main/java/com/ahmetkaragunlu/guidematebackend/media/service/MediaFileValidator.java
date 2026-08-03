package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.Map;

@Component
public class MediaFileValidator {

    private static final int SIGNATURE_LENGTH = 12;
    private static final int MAX_ORIGINAL_FILE_NAME_LENGTH = 255;
    private static final Map<String, String> EXTENSIONS = Map.of(
            "image/jpeg", "jpg",
            "image/png", "png",
            "image/webp", "webp"
    );

    private final long maxFileSizeBytes;

    public MediaFileValidator(MediaProperties properties) {
        this.maxFileSizeBytes = properties.maxFileSize().toBytes();
    }

    public ValidatedMedia validate(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new BusinessException(ErrorCode.MEDIA_INVALID_TYPE);
        }
        if (file.getSize() > maxFileSizeBytes) {
            throw new BusinessException(ErrorCode.MEDIA_TOO_LARGE);
        }

        String declaredContentType = normalizeContentType(file.getContentType());
        String detectedContentType = detectContentType(file);
        if (!EXTENSIONS.containsKey(declaredContentType)
                || !declaredContentType.equals(detectedContentType)) {
            throw new BusinessException(ErrorCode.MEDIA_INVALID_TYPE);
        }

        String extension = EXTENSIONS.get(detectedContentType);
        return new ValidatedMedia(
                detectedContentType,
                extension,
                safeOriginalFileName(file.getOriginalFilename(), extension),
                file.getSize()
        );
    }

    private String detectContentType(MultipartFile file) {
        try (InputStream input = file.getInputStream()) {
            byte[] signature = input.readNBytes(SIGNATURE_LENGTH);
            if (isJpeg(signature)) {
                return "image/jpeg";
            }
            if (isPng(signature)) {
                return "image/png";
            }
            if (isWebp(signature)) {
                return "image/webp";
            }
            throw new BusinessException(ErrorCode.MEDIA_INVALID_TYPE);
        } catch (IOException exception) {
            throw new BusinessException(ErrorCode.MEDIA_STORAGE_FAILED, exception);
        }
    }

    private boolean isJpeg(byte[] bytes) {
        return bytes.length >= 3
                && unsigned(bytes[0]) == 0xFF
                && unsigned(bytes[1]) == 0xD8
                && unsigned(bytes[2]) == 0xFF;
    }

    private boolean isPng(byte[] bytes) {
        int[] signature = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        if (bytes.length < signature.length) {
            return false;
        }
        for (int index = 0; index < signature.length; index++) {
            if (unsigned(bytes[index]) != signature[index]) {
                return false;
            }
        }
        return true;
    }

    private boolean isWebp(byte[] bytes) {
        return bytes.length >= SIGNATURE_LENGTH
                && bytes[0] == 'R'
                && bytes[1] == 'I'
                && bytes[2] == 'F'
                && bytes[3] == 'F'
                && bytes[8] == 'W'
                && bytes[9] == 'E'
                && bytes[10] == 'B'
                && bytes[11] == 'P';
    }

    private int unsigned(byte value) {
        return Byte.toUnsignedInt(value);
    }

    private String normalizeContentType(String contentType) {
        if (contentType == null) {
            return "";
        }
        return contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
    }

    private String safeOriginalFileName(String originalFileName, String extension) {
        String candidate = originalFileName == null ? "" : originalFileName.replace('\\', '/');
        int lastSeparator = candidate.lastIndexOf('/');
        if (lastSeparator >= 0) {
            candidate = candidate.substring(lastSeparator + 1);
        }
        candidate = candidate.replaceAll("\\p{Cntrl}", "").trim();
        if (candidate.isBlank()) {
            candidate = "upload." + extension;
        }
        return candidate.length() <= MAX_ORIGINAL_FILE_NAME_LENGTH
                ? candidate
                : candidate.substring(0, MAX_ORIGINAL_FILE_NAME_LENGTH);
    }
}
