package com.ahmetkaragunlu.guidematebackend.common.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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

    @Test
    @WithMockUser(roles = "TOURIST")
    void requiresIdempotencyKeyForTourCheckout() throws Exception {
        mockMvc.perform(post("/api/v1/payments/checkout/tour")
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {
                                  "sessionId": "%s",
                                  "participantCount": 1,
                                  "method": "WALLET"
                                }
                                """.formatted(UUID.randomUUID())))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));
    }

    @Test
    @WithMockUser(roles = "TOURIST")
    void requiresIdempotencyKeyForReservationCancellation() throws Exception {
        mockMvc.perform(post("/api/v1/reservations/{reservationId}/cancel", UUID.randomUUID())
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {"version": 0, "reason": "Plans changed"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));
    }

    @Test
    @WithMockUser(roles = "TOURIST")
    void rejectsReviewRatingOutsidePublicContract() throws Exception {
        mockMvc.perform(post("/api/v1/reservations/{reservationId}/reviews", UUID.randomUUID())
                        .contentType(APPLICATION_JSON)
                        .content("""
                                {"rating": 6, "comment": "Invalid rating"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.fieldErrors[0].field").value("rating"));
    }

    @Test
    void requiresTokenForPublicIyzicoCallback() throws Exception {
        mockMvc.perform(post("/api/v1/payments/iyzico/callback")
                        .contentType(APPLICATION_FORM_URLENCODED))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));
    }

    @Test
    void requiresSignatureForPublicIyzicoWebhook() throws Exception {
        mockMvc.perform(post("/api/v1/payments/iyzico/webhook")
                        .contentType(APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));
    }
}
