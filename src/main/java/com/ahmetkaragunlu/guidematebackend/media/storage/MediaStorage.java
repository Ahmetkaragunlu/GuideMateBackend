package com.ahmetkaragunlu.guidematebackend.media.storage;

import org.springframework.core.io.Resource;

import java.io.InputStream;
import java.util.Optional;

public interface MediaStorage {

    void store(String storageKey, InputStream content);

    Optional<Resource> load(String storageKey);

    void delete(String storageKey);
}
