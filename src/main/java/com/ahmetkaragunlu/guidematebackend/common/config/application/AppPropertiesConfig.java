package com.ahmetkaragunlu.guidematebackend.common.config.application;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(AppProperties.class)
public class AppPropertiesConfig {
}
