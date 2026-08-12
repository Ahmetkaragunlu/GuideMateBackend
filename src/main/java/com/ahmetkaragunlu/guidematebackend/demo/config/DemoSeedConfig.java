package com.ahmetkaragunlu.guidematebackend.demo.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Profile("local")
@Configuration
@EnableConfigurationProperties(DemoSeedProperties.class)
public class DemoSeedConfig {
}
