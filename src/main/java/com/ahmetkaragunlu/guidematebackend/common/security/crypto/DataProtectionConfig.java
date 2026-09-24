package com.ahmetkaragunlu.guidematebackend.common.security.crypto;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(DataProtectionProperties.class)
public class DataProtectionConfig {
}
