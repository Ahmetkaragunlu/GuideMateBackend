package com.ahmetkaragunlu.guidematebackend.common.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(DataProtectionProperties.class)
public class DataProtectionConfig {
}
