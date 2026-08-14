package com.ahmetkaragunlu.guidematebackend.common.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class HttpSecurityContractTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void rejectsAnonymousAccessToAuthenticatedEndpointWithStableCode() throws Exception {
        mockMvc.perform(get("/api/v1/chats"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    @WithMockUser(roles = "TOURIST")
    void rejectsTouristAccessToAdminEndpoint() throws Exception {
        mockMvc.perform(get("/api/v1/admin/tour-reviews"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    void allowsAnonymousMediaLookupToReachResourcePolicy() throws Exception {
        mockMvc.perform(get("/api/v1/media/{mediaId}/content", UUID.randomUUID()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("MEDIA_NOT_FOUND"));
    }
}
