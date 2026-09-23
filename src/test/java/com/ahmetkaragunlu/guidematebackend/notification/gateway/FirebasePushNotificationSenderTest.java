package com.ahmetkaragunlu.guidematebackend.notification.gateway;

import com.google.firebase.messaging.FirebaseMessaging;
import com.google.firebase.messaging.FirebaseMessagingException;
import com.google.firebase.messaging.Message;
import com.google.firebase.messaging.MessagingErrorCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FirebasePushNotificationSenderTest {

    @Mock private FirebaseMessaging firebaseMessaging;

    @Test
    void sendsHighPriorityDataMessageToFirebaseInstallation() throws Exception {
        FirebasePushNotificationSender sender = new FirebasePushNotificationSender(firebaseMessaging);
        when(firebaseMessaging.send(any(Message.class))).thenReturn("message-id");

        PushSendResult result = sender.send("installation-id", Map.of("type", "CHAT_MESSAGE"));

        assertThat(result).isEqualTo(PushSendResult.sent());
    }

    @Test
    void marksUnregisteredInstallationAsInvalid() throws Exception {
        FirebaseMessagingException failure = org.mockito.Mockito.mock(FirebaseMessagingException.class);
        when(failure.getMessagingErrorCode()).thenReturn(MessagingErrorCode.UNREGISTERED);
        when(firebaseMessaging.send(any(Message.class))).thenThrow(failure);

        assertThat(new FirebasePushNotificationSender(firebaseMessaging).send("stale-id", Map.of()))
                .isEqualTo(PushSendResult.invalidRegistration());
    }

    @Test
    void keepsRetryableFirebaseFailureDistinctFromInvalidRegistration() throws Exception {
        FirebaseMessagingException failure = org.mockito.Mockito.mock(FirebaseMessagingException.class);
        when(failure.getMessagingErrorCode()).thenReturn(MessagingErrorCode.UNAVAILABLE);
        when(firebaseMessaging.send(any(Message.class))).thenThrow(failure);

        assertThat(new FirebasePushNotificationSender(firebaseMessaging).send("active-id", Map.of()))
                .isEqualTo(PushSendResult.failed());
    }
}
