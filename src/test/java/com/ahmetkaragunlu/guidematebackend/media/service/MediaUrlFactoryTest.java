package com.ahmetkaragunlu.guidematebackend.media.service;

import com.ahmetkaragunlu.guidematebackend.common.config.AppProperties;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class MediaUrlFactoryTest {

    @Test
    void buildsCanonicalContentUrlFromNormalizedPublicBaseUrl() {
        UUID mediaId = UUID.randomUUID();
        MediaUrlFactory factory = new MediaUrlFactory(
                new AppProperties(URI.create("https://api.guidemate.test/"))
        );

        assertThat(factory.contentUrl(mediaId))
                .isEqualTo("https://api.guidemate.test/api/v1/media/" + mediaId + "/content");
    }
}
