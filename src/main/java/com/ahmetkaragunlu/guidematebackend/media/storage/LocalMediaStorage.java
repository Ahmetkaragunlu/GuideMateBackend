package com.ahmetkaragunlu.guidematebackend.media.storage;

import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Optional;

@Component
public class LocalMediaStorage implements MediaStorage {

    private final Path root;

    public LocalMediaStorage(MediaProperties properties) {
        if (!properties.storageRoot().isAbsolute()) {
            throw new IllegalStateException("MEDIA_STORAGE_ROOT must be an absolute path");
        }
        this.root = properties.storageRoot().toAbsolutePath().normalize();
        try {
            Files.createDirectories(root);
        } catch (IOException exception) {
            throw new MediaStorageException("Media storage root could not be initialized", exception);
        }
    }

    @Override
    public void store(String storageKey, InputStream content) {
        Path target = resolve(storageKey);
        Path temporaryFile = null;
        try (content) {
            temporaryFile = Files.createTempFile(root, "upload-", ".tmp");
            Files.copy(content, temporaryFile, StandardCopyOption.REPLACE_EXISTING);
            moveAtomically(temporaryFile, target);
        } catch (IOException exception) {
            throw new MediaStorageException("Media content could not be stored", exception);
        } finally {
            deleteTemporaryFile(temporaryFile);
        }
    }

    @Override
    public Optional<Resource> load(String storageKey) {
        Path path = resolve(storageKey);
        if (!Files.isRegularFile(path)) {
            return Optional.empty();
        }
        return Optional.of(new FileSystemResource(path));
    }

    @Override
    public void delete(String storageKey) {
        try {
            Files.deleteIfExists(resolve(storageKey));
        } catch (IOException exception) {
            throw new MediaStorageException("Media content could not be deleted", exception);
        }
    }

    private Path resolve(String storageKey) {
        Path resolved = root.resolve(storageKey).normalize();
        if (!resolved.startsWith(root)) {
            throw new MediaStorageException("Invalid media storage key");
        }
        return resolved;
    }

    private void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target);
        }
    }

    private void deleteTemporaryFile(Path temporaryFile) {
        if (temporaryFile == null) {
            return;
        }
        try {
            Files.deleteIfExists(temporaryFile);
        } catch (IOException ignored) {
            // Preserve the original storage result when best-effort temporary cleanup fails.
        }
    }
}
