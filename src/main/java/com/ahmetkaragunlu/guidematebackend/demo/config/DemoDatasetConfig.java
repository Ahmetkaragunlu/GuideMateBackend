package com.ahmetkaragunlu.guidematebackend.demo.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile(DemoTargetSafetyPolicy.DEMO_PROFILE)
@Configuration
@EnableConfigurationProperties(DemoDatasetProperties.class)
public class DemoDatasetConfig {
}
