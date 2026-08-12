package com.ahmetkaragunlu.guidematebackend.notification.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class NotificationRetryStateTest {

    @Test
    void enforcesRetryTimeAndAttemptLimit() {
        Notification notification = new Notification(
                mock(User.class),
                NotificationType.PAYMENT_SUCCEEDED,
                null,
                "{}",
                NotificationPushStatus.PENDING
        );
        Instant firstAttempt = Instant.parse("2026-08-13T00:00:00Z");
        Duration retryDelay = Duration.ofMinutes(5);

        notification.markPushAttempt(firstAttempt, firstAttempt.plus(retryDelay));

        assertThat(notification.canAttemptPush(firstAttempt.plusSeconds(60), 2)).isFalse();
        assertThat(notification.canAttemptPush(firstAttempt.plus(retryDelay), 2)).isTrue();

        notification.markPushAttempt(
                firstAttempt.plus(retryDelay),
                firstAttempt.plus(retryDelay.multipliedBy(2))
        );

        assertThat(notification.canAttemptPush(firstAttempt.plus(Duration.ofHours(1)), 2)).isFalse();
        assertThat(notification.getPushAttemptCount()).isEqualTo(2);
    }
}
