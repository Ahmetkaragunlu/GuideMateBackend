package com.ahmetkaragunlu.guidematebackend.tour.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(TourProperties.class)
public class TourConfig {
}
