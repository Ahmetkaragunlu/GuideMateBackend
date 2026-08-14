package com.ahmetkaragunlu.guidematebackend.notification;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CommunicationOpenApiContractTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publishesNotificationDeviceAndChatContracts() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/notifications']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/notifications/unread-count']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/notifications/{notificationId}/read']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/notifications/read-all']").exists())
                .andExpect(jsonPath("$.components.schemas.NotificationResponse.properties.actorDisplayName")
                        .exists())
                .andExpect(jsonPath("$.paths['/api/v1/notifications/preferences']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/devices/fcm-registration']").exists())
                .andExpect(jsonPath(
                        "$.paths['/api/v1/devices/fcm-registration/{installationId}']"
                ).exists())
                .andExpect(jsonPath("$.paths['/api/v1/chats/with-user/{remoteUserId}']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/chats']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/chats/{chatId}/messages']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/chats/{chatId}/read']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/chats/unread-count']").exists())
                .andExpect(jsonPath(
                        "$.components.schemas.UpdateNotificationPreferenceRequest.properties.securityAlertsEnabled"
                ).doesNotExist())
                .andExpect(jsonPath(
                        "$.components.schemas.NotificationPreferenceResponse.properties.securityAlertsEnabled"
                ).exists())
                .andExpect(jsonPath(
                        "$.components.schemas.RegisterDeviceRegistrationRequest.properties.firebaseInstallationId"
                ).exists())
                .andExpect(jsonPath(
                        "$.components.schemas.DeviceRegistrationResponse.properties.firebaseInstallationId"
                ).doesNotExist())
                .andExpect(jsonPath("$.components.schemas.SendChatMessageRequest.required").isArray());
    }
}
