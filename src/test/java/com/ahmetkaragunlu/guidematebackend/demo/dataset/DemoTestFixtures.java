package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

final class DemoTestFixtures {

    static final Instant REFERENCE_INSTANT = Instant.parse("2026-08-28T12:00:00Z");
    static final String PASSWORD = "DemoPass123!";

    private DemoTestFixtures() {
    }

    static List<DemoFixtureData.Media> mediaFixtures() {
        List<DemoFixtureData.Media> fixtures = new ArrayList<>(480);
        for (long userId = 1001; userId <= 1250; userId++) {
            fixtures.add(avatar(userId));
        }
        for (long userId = 2001; userId <= 2050; userId++) {
            fixtures.add(avatar(userId));
        }
        for (int tourIndex = 1; tourIndex <= 180; tourIndex++) {
            fixtures.add(new DemoFixtureData.Media(
                    DemoSeedIds.uuid("tour-cover-" + tourIndex),
                    2006 + (tourIndex - 1) % 45,
                    "TOUR_COVER",
                    "seed-v1/tours/tour-" + tourIndex + ".jpg",
                    "tour-cover.jpg",
                    "image/jpeg",
                    1
            ));
        }
        return List.copyOf(fixtures);
    }

    private static DemoFixtureData.Media avatar(long userId) {
        return new DemoFixtureData.Media(
                DemoSeedIds.uuid("avatar-" + userId),
                userId,
                "USER_AVATAR",
                "seed-v1/avatars/user-" + userId + ".png",
                "avatar.png",
                "image/png",
                1
        );
    }
}
