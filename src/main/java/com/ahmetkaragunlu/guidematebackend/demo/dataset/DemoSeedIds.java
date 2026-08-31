package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

final class DemoSeedIds {

    private static final String NAMESPACE = "guidemate-demo-v1:";

    private DemoSeedIds() {
    }

    static UUID uuid(String key) {
        return UUID.nameUUIDFromBytes((NAMESPACE + key).getBytes(StandardCharsets.UTF_8));
    }
}
