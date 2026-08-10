package com.ahmetkaragunlu.guidematebackend.payment.config;

import com.iyzipay.Options;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(PaymentProperties.class)
public class PaymentConfig {

    @Bean
    public Options iyzicoOptions(PaymentProperties properties) {
        Options options = new Options();
        options.setApiKey(properties.iyzico().apiKey());
        options.setSecretKey(properties.iyzico().secretKey());
        options.setBaseUrl(properties.iyzico().baseUrl());
        return options;
    }
}
