package com.ahmetkaragunlu.guidematebackend.notification;

import com.ahmetkaragunlu.guidematebackend.notification.domain.DeviceRegistration;
import com.ahmetkaragunlu.guidematebackend.notification.domain.Notification;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPushStatus;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.gateway.PushNotificationSender;
import com.ahmetkaragunlu.guidematebackend.notification.gateway.PushSendResult;
import com.ahmetkaragunlu.guidematebackend.notification.repository.DeviceRegistrationRepository;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPushDeliveryService;
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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringBootTest
@ActiveProfiles("test")
class NotificationPushDeliveryServiceTest {

    @Autowired
    private NotificationPushDeliveryService deliveryService;

    @Autowired
    private NotificationRepository notificationRepository;

    @Autowired
    private DeviceRegistrationRepository registrationRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @MockitoBean
    private PushNotificationSender pushNotificationSender;

    @Test
    void sendsOutsideDatabaseTransactionWithWhitelistedSemanticPayloadOnly() {
        String firebaseInstallationId = "test-fid-" + UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        Fixture fixture = new TransactionTemplate(transactionManager).execute(status -> {
            User user = createUser("push-delivery@example.com");
            DeviceRegistration registration = registrationRepository.save(new DeviceRegistration(
                    user,
                    UUID.randomUUID(),
                    firebaseInstallationId,
                    Instant.parse("2026-08-11T00:00:00Z")
            ));
            Notification notification = notificationRepository.save(new Notification(
                    user,
                    NotificationType.SECURITY_ALERT,
                    null,
                    "{\"tourId\":\"" + tourId + "\","
                            + "\"securityEvent\":\"PASSWORD_CHANGED\","
                            + "\"tourTitle\":\"Hidden from push\","
                            + "\"accountSecret\":\"must-not-leak\"}",
                    NotificationPushStatus.PENDING
            ));
            return new Fixture(notification.getId(), registration.getId());
        });

        when(pushNotificationSender.isAvailable()).thenReturn(true);
        when(pushNotificationSender.send(eq(firebaseInstallationId), anyMap())).thenAnswer(invocation -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            Map<String, String> data = invocation.getArgument(1);
            assertThat(data).containsEntry("notificationId", fixture.notificationId().toString());
            assertThat(data).containsEntry("type", NotificationType.SECURITY_ALERT.name());
            assertThat(data).containsEntry("tourId", tourId.toString());
            assertThat(data).containsEntry("securityEvent", "PASSWORD_CHANGED");
            assertThat(data).doesNotContainKeys(
                    "tourTitle",
                    "accountSecret",
                    "route",
                    "body"
            );
            return PushSendResult.sent();
        });

        deliveryService.deliver(fixture.notificationId());

        assertThat(notificationRepository.findById(fixture.notificationId()).orElseThrow().getPushStatus())
                .isEqualTo(NotificationPushStatus.SENT);
        assertThat(registrationRepository.findById(fixture.registrationId()).orElseThrow().isActive())
                .isTrue();
        verify(pushNotificationSender).send(eq(firebaseInstallationId), anyMap());
    }

    private User createUser(String email) {
        Role role = roleRepository.findByName(RoleType.ROLE_GUIDE.name()).orElseThrow();
        User user = new User();
        user.setFirstName("Push");
        user.setLastName("Recipient");
        user.setEmail(email);
        user.setPassword("not-used");
        user.setRole(role);
        user.setRoleSelected(true);
        user.setAccountStatus(AccountStatus.ACTIVE);
        return userRepository.save(user);
    }

    private record Fixture(UUID notificationId, UUID registrationId) {
    }
}
