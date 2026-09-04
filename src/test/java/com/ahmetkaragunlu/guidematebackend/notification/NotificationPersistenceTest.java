package com.ahmetkaragunlu.guidematebackend.notification;

import com.ahmetkaragunlu.guidematebackend.notification.domain.Notification;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationTargetType;
import com.ahmetkaragunlu.guidematebackend.notification.dto.MarkRelatedNotificationsReadRequest;
import com.ahmetkaragunlu.guidematebackend.notification.dto.NotificationResponse;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPayloadCodec;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationService;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
class NotificationPersistenceTest {

    @Autowired
    private NotificationPublisher notificationPublisher;
    @Autowired
    private NotificationRepository notificationRepository;
    @Autowired
    private NotificationPayloadCodec payloadCodec;
    @Autowired
    private NotificationService notificationService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    @Test
    void storesJsonPayloadAndReturnsExistingNotificationForDeduplicationKey() {
        User recipient = createUser();
        String deduplicationKey = "tour-reminder-" + UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        NotificationCommand command = new NotificationCommand(
                recipient.getId(),
                NotificationType.UPCOMING_TOUR_REMINDER,
                null,
                Map.of("tourId", tourId.toString(), "minutesUntilStart", 60),
                deduplicationKey
        );

        UUID firstId = notificationPublisher.publish(command);
        UUID retryId = notificationPublisher.publish(command);

        assertThat(retryId).isEqualTo(firstId);
        Notification stored = notificationRepository
                .findByRecipient_IdAndTypeAndDeduplicationKey(
                        recipient.getId(),
                        NotificationType.UPCOMING_TOUR_REMINDER,
                        deduplicationKey
                )
                .orElseThrow();
        assertThat(payloadCodec.decode(stored.getPayloadJson()))
                .containsEntry("tourId", tourId.toString())
                .containsEntry("minutesUntilStart", 60);
    }

    @Test
    void returnsActorDisplayNameForUserNotificationsAndNullForSystemNotifications() {
        User recipient = createUser();
        User actor = createUser();
        notificationPublisher.publish(new NotificationCommand(
                recipient.getId(),
                NotificationType.TOUR_PURCHASED,
                actor.getId(),
                Map.of("tourId", UUID.randomUUID().toString())
        ));
        notificationPublisher.publish(new NotificationCommand(
                recipient.getId(),
                NotificationType.EARNING_AVAILABLE,
                null,
                Map.of("earningId", UUID.randomUUID().toString())
        ));

        var notifications = notificationService.getNotifications(recipient, 0, 20).content();

        assertThat(notifications)
                .filteredOn(notification -> notification.type() == NotificationType.TOUR_PURCHASED)
                .singleElement()
                .satisfies(notification -> {
                    assertThat(notification.actorId()).isEqualTo(actor.getId());
                    assertThat(notification.actorDisplayName()).isEqualTo(actor.displayName());
                });
        assertThat(notifications)
                .filteredOn(notification -> notification.type() == NotificationType.EARNING_AVAILABLE)
                .singleElement()
                .satisfies(notification -> {
                    assertThat(notification.actorId()).isNull();
                    assertThat(notification.actorDisplayName()).isNull();
                });
    }

    @Test
    void marksOnlyOwnedNotificationsForTargetAndRepeatedRequestIsIdempotent() {
        User recipient = createUser();
        User anotherRecipient = createUser();
        UUID chatId = UUID.randomUUID();
        UUID unrelatedChatId = UUID.randomUUID();
        notificationPublisher.publish(new NotificationCommand(
                recipient.getId(),
                NotificationType.CHAT_MESSAGE,
                anotherRecipient.getId(),
                Map.of("chatId", chatId.toString())
        ));
        notificationPublisher.publish(new NotificationCommand(
                recipient.getId(),
                NotificationType.CHAT_MESSAGE,
                anotherRecipient.getId(),
                Map.of("chatId", chatId.toString())
        ));
        notificationPublisher.publish(new NotificationCommand(
                recipient.getId(),
                NotificationType.CHAT_MESSAGE,
                anotherRecipient.getId(),
                Map.of("chatId", unrelatedChatId.toString())
        ));
        notificationPublisher.publish(new NotificationCommand(
                anotherRecipient.getId(),
                NotificationType.CHAT_MESSAGE,
                recipient.getId(),
                Map.of("chatId", chatId.toString())
        ));
        var request = new MarkRelatedNotificationsReadRequest(NotificationTargetType.CHAT, chatId);

        var firstResult = notificationService.markRelatedRead(recipient, request);
        var repeatedResult = notificationService.markRelatedRead(recipient, request);

        assertThat(firstResult.unreadCount()).isEqualTo(1);
        assertThat(repeatedResult.unreadCount()).isEqualTo(1);
        assertThat(notificationService.unreadCount(anotherRecipient).unreadCount()).isEqualTo(1);
        assertThat(notificationService.getNotifications(recipient, 0, 20).content())
                .filteredOn(notification -> chatId.toString().equals(notification.payload().get("chatId")))
                .allMatch(NotificationResponse::read);
        assertThat(notificationService.getNotifications(recipient, 0, 20).content())
                .filteredOn(notification -> unrelatedChatId.toString().equals(notification.payload().get("chatId")))
                .noneMatch(NotificationResponse::read);
    }

    private User createUser() {
        Role role = roleRepository.findByName(RoleType.ROLE_TOURIST.name()).orElseThrow();
        User user = new User();
        user.setFirstName("Notification");
        user.setLastName("Recipient");
        user.setEmail("notification-" + UUID.randomUUID() + "@example.com");
        user.setPassword("not-used");
        user.setRole(role);
        user.setRoleSelected(true);
        user.setAccountStatus(AccountStatus.ACTIVE);
        return userRepository.saveAndFlush(user);
    }
}
