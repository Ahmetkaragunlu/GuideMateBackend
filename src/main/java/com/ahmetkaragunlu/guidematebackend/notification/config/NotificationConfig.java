package com.ahmetkaragunlu.guidematebackend.notification.config;

import com.ahmetkaragunlu.guidematebackend.notification.gateway.FirebasePushNotificationSender;
import com.ahmetkaragunlu.guidematebackend.notification.gateway.NoOpPushNotificationSender;
import com.ahmetkaragunlu.guidematebackend.notification.gateway.PushNotificationSender;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import com.google.firebase.messaging.FirebaseMessaging;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

@Configuration
@EnableAsync
@EnableConfigurationProperties(FcmProperties.class)
public class NotificationConfig {

    @Bean(destroyMethod = "delete")
    @ConditionalOnProperty(name = "notification.fcm.enabled", havingValue = "true")
    public FirebaseApp notificationFirebaseApp(FcmProperties properties) throws IOException {
        FirebaseOptions options = FirebaseOptions.builder()
                .setCredentials(loadCredentials(properties.credentialsPath()))
                .build();
        return FirebaseApp.initializeApp(options, "guidemate-notifications");
    }

    @Bean
    @ConditionalOnProperty(name = "notification.fcm.enabled", havingValue = "true")
    public PushNotificationSender firebasePushNotificationSender(FirebaseApp notificationFirebaseApp) {
        return new FirebasePushNotificationSender(FirebaseMessaging.getInstance(notificationFirebaseApp));
    }

    @Bean
    @ConditionalOnMissingBean(PushNotificationSender.class)
    public PushNotificationSender noOpPushNotificationSender() {
        return new NoOpPushNotificationSender();
    }

    @Bean(name = "notificationTaskExecutor")
    public TaskExecutor notificationTaskExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("notification-");
        executor.setWaitForTasksToCompleteOnShutdown(true);
        executor.initialize();
        return executor;
    }

    private GoogleCredentials loadCredentials(String credentialsPath) throws IOException {
        if (credentialsPath == null || credentialsPath.isBlank()) {
            return GoogleCredentials.getApplicationDefault();
        }
        try (InputStream input = Files.newInputStream(Path.of(credentialsPath))) {
            return GoogleCredentials.fromStream(input);
        }
    }
}
