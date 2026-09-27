package com.ahmetkaragunlu.guidematebackend.notification;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.support.persistence.PersistenceTestFixtures;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.ahmetkaragunlu.guidematebackend.support.persistence.ConcurrentTestExecutor.run;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Import(PersistenceTestFixtures.class)
class NotificationDeduplicationIntegrationTest {

    @Autowired
    private PersistenceTestFixtures fixtures;
    @Autowired
    private NotificationPublisher notificationPublisher;
    @Autowired
    private NotificationRepository notificationRepository;

    @Test
    void storesOneNotificationForConcurrentDeliveryOfSameDomainEvent() throws Exception {
        User recipient = fixtures.createUser(
                "notification-" + UUID.randomUUID() + "@example.com",
                RoleType.ROLE_TOURIST
        );
        String deduplicationKey = "reservation:" + UUID.randomUUID();
        NotificationCommand command = new NotificationCommand(
                recipient.getId(),
                NotificationType.RESERVATION_CONFIRMED,
                null,
                Map.of("reservationId", UUID.randomUUID().toString()),
                deduplicationKey
        );

        List<UUID> notificationIds = run(
                () -> notificationPublisher.publish(command),
                () -> notificationPublisher.publish(command)
        );

        assertThat(notificationIds).containsOnly(notificationIds.get(0));
        assertThat(notificationRepository.findByRecipient_IdAndTypeAndDeduplicationKey(
                recipient.getId(),
                NotificationType.RESERVATION_CONFIRMED,
                deduplicationKey
        )).hasValueSatisfying(notification ->
                assertThat(notification.getId()).isEqualTo(notificationIds.get(0)));
    }
}
