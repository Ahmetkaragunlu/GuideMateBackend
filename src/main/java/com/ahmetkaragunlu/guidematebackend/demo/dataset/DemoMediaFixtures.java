package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Component
class DemoMediaFixtures {

    private static final int AVATAR_SIZE = 256;
    private static final int TOUR_COUNT = 180;
    private static final int EXPECTED_SOURCE_COUNT = 24;
    private static final long MAX_FILE_SIZE = 5L * 1024 * 1024;
    private static final Set<Integer> MALE_TOURIST_NAME_POSITIONS =
            Set.of(4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24);
    private static final Set<Integer> MALE_GUIDE_NAME_POSITIONS =
            Set.of(2, 4, 6, 8, 10, 12, 14);
    private static final ClassPathResource SOURCE_MANIFEST =
            new ClassPathResource("demo/tour-cover-sources.tsv");

    private final Path root;

    DemoMediaFixtures(MediaProperties mediaProperties) {
        this.root = mediaProperties.storageRoot().toAbsolutePath().normalize();
    }

    List<DemoFixtureData.Media> prepare() {
        try {
            requireSafeRoot();
            List<SourceImage> sources = readSources();
            copyAttributionManifest();
            List<DemoFixtureData.Media> fixtures = new ArrayList<>(480);
            addAvatarFixtures(fixtures);
            addTourCoverFixtures(fixtures, sources);
            if (fixtures.size() != 480) {
                throw new IllegalStateException("Demo media fixture count is inconsistent");
            }
            return List.copyOf(fixtures);
        } catch (IOException exception) {
            throw new IllegalStateException("Demo media fixtures could not be prepared", exception);
        }
    }

    void verify(List<DemoFixtureData.Media> fixtures) {
        for (DemoFixtureData.Media fixture : fixtures) {
            Path file = resolve(fixture.storageKey());
            try {
                if (!Files.isRegularFile(file)
                        || Files.isSymbolicLink(file)
                        || Files.size(file) != fixture.sizeBytes()) {
                    throw new IllegalStateException("Demo media fixture is missing or inconsistent");
                }
            } catch (IOException exception) {
                throw new IllegalStateException("Demo media fixture could not be verified", exception);
            }
        }
    }

    private void addAvatarFixtures(List<DemoFixtureData.Media> fixtures) throws IOException {
        for (long userId = 1001; userId <= 1250; userId++) {
            fixtures.add(avatar(userId));
        }
        for (long userId = 2001; userId <= 2050; userId++) {
            fixtures.add(avatar(userId));
        }
    }

    private DemoFixtureData.Media avatar(long userId) throws IOException {
        String storageKey = String.format(Locale.ROOT, "seed-v1/avatars/user-%04d.png", userId);
        Path target = resolve(storageKey);
        Files.createDirectories(target.getParent());
        writeAvatar(target, avatarStyle(userId));
        return new DemoFixtureData.Media(
                DemoSeedIds.uuid("avatar-" + userId),
                userId,
                "USER_AVATAR",
                storageKey,
                "synthetic-avatar-" + userId + ".png",
                "image/png",
                checkedSize(target)
        );
    }

    private void addTourCoverFixtures(
            List<DemoFixtureData.Media> fixtures,
            List<SourceImage> sources
    ) throws IOException {
        Path sourceRoot = resolve("_sources");
        for (int tourIndex = 1; tourIndex <= TOUR_COUNT; tourIndex++) {
            SourceImage source = sources.get((tourIndex - 1) % sources.size());
            Path sourceFile = sourceRoot.resolve(source.slug() + ".jpg").normalize();
            requireInsideRoot(sourceFile);
            validateSourceImage(sourceFile);

            String storageKey = String.format(
                    Locale.ROOT,
                    "seed-v1/tours/tour-%03d.jpg",
                    tourIndex
            );
            Path target = resolve(storageKey);
            Files.createDirectories(target.getParent());
            copyAtomically(sourceFile, target);
            long ownerId = 2006 + (tourIndex - 1) % 45;
            fixtures.add(new DemoFixtureData.Media(
                    DemoSeedIds.uuid("tour-cover-" + tourIndex),
                    ownerId,
                    "TOUR_COVER",
                    storageKey,
                    source.slug() + ".jpg",
                    "image/jpeg",
                    checkedSize(target)
            ));
        }
    }

    private List<SourceImage> readSources() throws IOException {
        List<String> lines;
        try (InputStream input = SOURCE_MANIFEST.getInputStream()) {
            lines = new String(input.readAllBytes(), StandardCharsets.UTF_8).lines().toList();
        }
        List<SourceImage> sources = lines.stream()
                .skip(1)
                .filter(line -> !line.isBlank())
                .map(line -> line.split("\\t", -1))
                .map(columns -> {
                    if (columns.length < 8 || columns[0].isBlank()) {
                        throw new IllegalStateException("Demo tour cover manifest is malformed");
                    }
                    return new SourceImage(columns[0]);
                })
                .toList();
        if (sources.size() != EXPECTED_SOURCE_COUNT
                || sources.stream().map(SourceImage::slug).distinct().count() != EXPECTED_SOURCE_COUNT) {
            throw new IllegalStateException("Demo tour cover manifest must contain 24 unique sources");
        }
        return sources;
    }

    private void copyAttributionManifest() throws IOException {
        Path target = resolve("ATTRIBUTION.tsv");
        try (InputStream input = SOURCE_MANIFEST.getInputStream()) {
            writeAtomically(input, target);
        }
    }

    private AvatarStyle avatarStyle(long userId) {
        if (userId >= 1001 && userId <= 1250) {
            int namePosition = 1 + (int) ((userId - 1001) % 24);
            return MALE_TOURIST_NAME_POSITIONS.contains(namePosition)
                    ? AvatarStyle.MALE
                    : AvatarStyle.FEMALE;
        }
        if (userId >= 2001 && userId <= 2050) {
            int namePosition = 1 + (int) ((userId - 2001) % 16);
            return MALE_GUIDE_NAME_POSITIONS.contains(namePosition)
                    ? AvatarStyle.MALE
                    : AvatarStyle.FEMALE;
        }
        throw new IllegalArgumentException("Unsupported demo avatar owner");
    }

    private void writeAvatar(Path target, AvatarStyle style) throws IOException {
        BufferedImage image = new BufferedImage(AVATAR_SIZE, AVATAR_SIZE, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = image.createGraphics();
        try {
            graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            if (style == AvatarStyle.FEMALE) {
                drawFemaleAvatar(graphics);
            } else {
                drawMaleAvatar(graphics);
            }
        } finally {
            graphics.dispose();
        }

        Path temporary = Files.createTempFile(target.getParent(), "avatar-", ".tmp");
        try {
            if (!ImageIO.write(image, "png", temporary.toFile())) {
                throw new IOException("PNG encoder is unavailable");
            }
            moveAtomically(temporary, target);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void drawFemaleAvatar(Graphics2D graphics) {
        graphics.setColor(new Color(238, 178, 176));
        graphics.fillRect(0, 0, AVATAR_SIZE, AVATAR_SIZE);
        graphics.setColor(new Color(250, 218, 190));
        graphics.fillOval(-34, -46, 205, 205);

        graphics.setColor(new Color(76, 45, 42));
        graphics.fillRoundRect(62, 32, 132, 184, 68, 68);
        graphics.setColor(new Color(244, 190, 149));
        graphics.fillRoundRect(109, 137, 38, 47, 18, 18);
        graphics.fillOval(82, 50, 94, 114);
        graphics.setColor(new Color(76, 45, 42));
        graphics.fillOval(79, 36, 100, 59);
        graphics.fillOval(65, 52, 38, 133);
        graphics.fillOval(155, 52, 38, 133);

        graphics.setColor(new Color(255, 232, 224));
        graphics.fillRoundRect(41, 172, 176, 108, 76, 76);
        drawFace(graphics);
    }

    private void drawMaleAvatar(Graphics2D graphics) {
        graphics.setColor(new Color(91, 157, 164));
        graphics.fillRect(0, 0, AVATAR_SIZE, AVATAR_SIZE);
        graphics.setColor(new Color(154, 205, 199));
        graphics.fillOval(96, -55, 220, 220);

        graphics.setColor(new Color(230, 170, 126));
        graphics.fillRoundRect(109, 137, 38, 47, 18, 18);
        graphics.fillOval(82, 50, 94, 114);
        graphics.setColor(new Color(48, 58, 58));
        graphics.fillRoundRect(78, 36, 102, 60, 36, 36);
        graphics.fillRect(82, 70, 14, 31);
        graphics.fillRect(160, 70, 14, 25);

        graphics.setColor(new Color(226, 239, 235));
        graphics.fillRoundRect(41, 172, 176, 108, 76, 76);
        graphics.setColor(new Color(53, 101, 108));
        graphics.fillRoundRect(105, 172, 46, 108, 18, 18);
        drawFace(graphics);
    }

    private void drawFace(Graphics2D graphics) {
        graphics.setColor(new Color(53, 48, 48));
        graphics.fillOval(105, 105, 8, 10);
        graphics.fillOval(143, 105, 8, 10);
        graphics.setColor(new Color(168, 83, 82));
        graphics.fillOval(120, 136, 17, 5);
    }

    private void validateSourceImage(Path sourceFile) throws IOException {
        if (!Files.isRegularFile(sourceFile)
                || Files.isSymbolicLink(sourceFile)
                || checkedSize(sourceFile) <= 0
                || ImageIO.read(sourceFile.toFile()) == null) {
            throw new IllegalStateException("A prepared Wikimedia source image is missing or invalid");
        }
    }

    private long checkedSize(Path file) throws IOException {
        long size = Files.size(file);
        if (size <= 0 || size > MAX_FILE_SIZE) {
            throw new IllegalStateException("Demo media fixture exceeds the supported size");
        }
        return size;
    }

    private void copyAtomically(Path source, Path target) throws IOException {
        try (InputStream input = Files.newInputStream(source)) {
            writeAtomically(input, target);
        }
    }

    private void writeAtomically(InputStream input, Path target) throws IOException {
        Files.createDirectories(target.getParent());
        Path temporary = Files.createTempFile(target.getParent(), "fixture-", ".tmp");
        try {
            Files.copy(input, temporary, StandardCopyOption.REPLACE_EXISTING);
            moveAtomically(temporary, target);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(
                    source,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING
            );
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private void requireSafeRoot() throws IOException {
        if (!root.isAbsolute() || Files.isSymbolicLink(root) || Files.isSymbolicLink(root.getParent())) {
            throw new IllegalStateException("Demo media root is unsafe");
        }
        Files.createDirectories(root);
    }

    private Path resolve(String storageKey) {
        Path path = root.resolve(storageKey).normalize();
        requireInsideRoot(path);
        return path;
    }

    private void requireInsideRoot(Path path) {
        if (!path.startsWith(root)) {
            throw new IllegalStateException("Demo media path escapes the isolated root");
        }
    }

    private record SourceImage(String slug) {
    }

    private enum AvatarStyle {
        FEMALE,
        MALE
    }
}
