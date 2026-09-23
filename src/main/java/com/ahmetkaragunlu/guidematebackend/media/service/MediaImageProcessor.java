package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import javax.imageio.IIOImage;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.ImageWriter;
import javax.imageio.stream.ImageInputStream;
import javax.imageio.stream.ImageOutputStream;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Iterator;

@Component
public class MediaImageProcessor {

    private static final String JPEG_CONTENT_TYPE = "image/jpeg";
    private static final String PNG_CONTENT_TYPE = "image/png";

    private final int maxImageWidth;
    private final int maxImageHeight;
    private final long maxImagePixels;

    public MediaImageProcessor(MediaProperties properties) {
        this.maxImageWidth = properties.maxImageWidth();
        this.maxImageHeight = properties.maxImageHeight();
        this.maxImagePixels = properties.maxImagePixels();
    }

    public ProcessedMedia process(MultipartFile file, ValidatedMedia validated) {
        try {
            byte[] uploadedContent = file.getBytes();
            BufferedImage image = decode(uploadedContent);
            OutputFormat outputFormat = outputFormat(validated.contentType());
            byte[] cleanContent = encode(image, outputFormat);
            return new ProcessedMedia(
                    cleanContent,
                    new ValidatedMedia(
                            outputFormat.contentType(),
                            outputFormat.extension(),
                            replaceExtension(validated.originalFileName(), outputFormat.extension()),
                            cleanContent.length
                    )
            );
        } catch (BusinessException exception) {
            throw exception;
        } catch (IOException | RuntimeException exception) {
            throw new BusinessException(ErrorCode.MEDIA_INVALID_TYPE, exception);
        }
    }

    private BufferedImage decode(byte[] uploadedContent) throws IOException {
        try (ImageInputStream input = ImageIO.createImageInputStream(new ByteArrayInputStream(uploadedContent))) {
            if (input == null) {
                throw invalidImage();
            }
            Iterator<ImageReader> readers = ImageIO.getImageReaders(input);
            if (!readers.hasNext()) {
                throw invalidImage();
            }

            ImageReader reader = readers.next();
            try {
                reader.setInput(input, true, true);
                validateDimensions(reader.getWidth(0), reader.getHeight(0));
                BufferedImage image = reader.read(0);
                if (image == null) {
                    throw invalidImage();
                }
                validateDimensions(image.getWidth(), image.getHeight());
                return image;
            } finally {
                reader.dispose();
            }
        }
    }

    private byte[] encode(BufferedImage source, OutputFormat outputFormat) throws IOException {
        BufferedImage image = outputFormat == OutputFormat.JPEG ? toRgb(source) : source;
        Iterator<ImageWriter> writers = ImageIO.getImageWritersByFormatName(outputFormat.formatName());
        if (!writers.hasNext()) {
            throw invalidImage();
        }

        ImageWriter writer = writers.next();
        try (ByteArrayOutputStream bytes = new ByteArrayOutputStream();
             ImageOutputStream output = ImageIO.createImageOutputStream(bytes)) {
            writer.setOutput(output);
            writer.write(null, new IIOImage(image, null, null), writer.getDefaultWriteParam());
            output.flush();
            return bytes.toByteArray();
        } finally {
            writer.dispose();
        }
    }

    private BufferedImage toRgb(BufferedImage source) {
        BufferedImage rgb = new BufferedImage(source.getWidth(), source.getHeight(), BufferedImage.TYPE_INT_RGB);
        int[] pixels = source.getRGB(0, 0, source.getWidth(), source.getHeight(), null, 0, source.getWidth());
        rgb.setRGB(0, 0, source.getWidth(), source.getHeight(), pixels, 0, source.getWidth());
        return rgb;
    }

    private void validateDimensions(int width, int height) {
        if (width <= 0 || height <= 0 || width > maxImageWidth || height > maxImageHeight
                || (long) width * height > maxImagePixels) {
            throw new BusinessException(ErrorCode.MEDIA_TOO_LARGE);
        }
    }

    private OutputFormat outputFormat(String contentType) {
        return JPEG_CONTENT_TYPE.equals(contentType) ? OutputFormat.JPEG : OutputFormat.PNG;
    }

    private String replaceExtension(String fileName, String extension) {
        int dot = fileName.lastIndexOf('.');
        String baseName = dot > 0 ? fileName.substring(0, dot) : fileName;
        return baseName + "." + extension;
    }

    private BusinessException invalidImage() {
        return new BusinessException(ErrorCode.MEDIA_INVALID_TYPE);
    }

    private enum OutputFormat {
        JPEG("jpeg", JPEG_CONTENT_TYPE, "jpg"),
        PNG("png", PNG_CONTENT_TYPE, "png");

        private final String formatName;
        private final String contentType;
        private final String extension;

        OutputFormat(String formatName, String contentType, String extension) {
            this.formatName = formatName;
            this.contentType = contentType;
            this.extension = extension;
        }

        String formatName() {
            return formatName;
        }

        String contentType() {
            return contentType;
        }

        String extension() {
            return extension;
        }
    }
}
