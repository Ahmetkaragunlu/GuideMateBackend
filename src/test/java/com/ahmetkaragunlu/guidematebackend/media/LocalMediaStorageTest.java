package com.ahmetkaragunlu.guidematebackend.media;

import com.ahmetkaragunlu.guidematebackend.media.config.MediaProperties;
import com.ahmetkaragunlu.guidematebackend.media.storage.LocalMediaStorage;
import com.ahmetkaragunlu.guidematebackend.media.storage.MediaStorageException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.util.unit.DataSize;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LocalMediaStorageTest {

    @TempDir
    Path storageRoot;

    @Test
    void storesLoadsAndDeletesContentInsideConfiguredRoot() throws Exception {
        LocalMediaStorage storage = storage();
        byte[] content = "media-content".getBytes(StandardCharsets.UTF_8);

        storage.store("asset.bin", new ByteArrayInputStream(content));

        assertThat(storage.load("asset.bin")).isPresent();
        assertThat(storage.load("asset.bin").orElseThrow().getContentAsByteArray())
                .isEqualTo(content);

        storage.delete("asset.bin");

        assertThat(storage.load("asset.bin")).isEmpty();
    }

    @Test
    void rejectsStorageKeyThatEscapesConfiguredRoot() {
        LocalMediaStorage storage = storage();

        assertThatThrownBy(() -> storage.store(
                "../outside.bin",
                new ByteArrayInputStream(new byte[]{1})
        )).isInstanceOf(MediaStorageException.class)
                .hasMessage("Invalid media storage key");
    }

    private LocalMediaStorage storage() {
        return new LocalMediaStorage(new MediaProperties(
                storageRoot,
                DataSize.ofMegabytes(5),
                Duration.ofHours(1)
        ));
    }
}
