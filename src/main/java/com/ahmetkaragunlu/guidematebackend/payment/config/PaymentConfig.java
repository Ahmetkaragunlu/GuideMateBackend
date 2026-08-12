package com.ahmetkaragunlu.guidematebackend.payment.config;

import com.iyzipay.Options;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.client.RestClient;

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

    @Bean
    public RestClient fxRestClient(PaymentProperties properties) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(properties.fx().connectTimeout());
        requestFactory.setReadTimeout(properties.fx().readTimeout());
        return RestClient.builder()
                .baseUrl(properties.fx().baseUrl().toString())
                .requestFactory(requestFactory)
                .build();
    }

    @Bean(name = "paymentTaskExecutor")
    public TaskExecutor paymentTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(2);
        executor.setQueueCapacity(50);
        executor.setThreadNamePrefix("payment-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.initialize();
        return executor;
    }
}
