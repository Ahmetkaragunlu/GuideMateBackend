package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideLevel;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GuideLevelPolicyTest {

    private final GuideLevelPolicy policy = new GuideLevelPolicy();

    @Test
    void resolvesExactProfessionalLevelThresholds() {
        assertThat(policy.resolve(4, 5.0, 100)).isEqualTo(GuideLevel.APPROVED);
        assertThat(policy.resolve(5, 3.7, 3)).isEqualTo(GuideLevel.SILVER);
        assertThat(policy.resolve(20, 4.5, 10)).isEqualTo(GuideLevel.SUPER);
        assertThat(policy.resolve(100, 4.8, 30)).isEqualTo(GuideLevel.LEGENDARY);
    }

    @Test
    void requiresEveryThresholdForHigherLevel() {
        assertThat(policy.resolve(100, 4.79, 30)).isEqualTo(GuideLevel.SUPER);
        assertThat(policy.resolve(20, 4.5, 9)).isEqualTo(GuideLevel.SILVER);
    }
}
