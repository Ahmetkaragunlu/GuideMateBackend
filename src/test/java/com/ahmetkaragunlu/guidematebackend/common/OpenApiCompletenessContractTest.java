package com.ahmetkaragunlu.guidematebackend.common;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class OpenApiCompletenessContractTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publishesCoreApiSurfaceAndHidesInternalSensitiveFields() throws Exception {
        String document = mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("GuideMate API"))
                .andExpect(jsonPath("$.info.version").value("v1"))
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.type").value("http"))
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"))
                .andExpect(jsonPath("$.paths['/api/v1/auth/register']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/auth/me']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/media']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/guides/{guideId}/public-profile']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/guide/tours']").exists())
                .andExpect(jsonPath("$.components.schemas.GuideTourCardResponse.properties.averageRating")
                        .exists())
                .andExpect(jsonPath("$.components.schemas.GuideTourCardResponse.properties.reviewCount")
                        .exists())
                .andExpect(jsonPath("$.components.schemas.GuideTourCardResponse.properties.netEarningsMinor")
                        .exists())
                .andExpect(jsonPath("$.components.schemas.GuideTourCardResponse.properties.capacity")
                        .exists())
                .andExpect(jsonPath("$.paths['/api/v1/tours/search']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/tour-sessions/{sessionId}']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/admin/tour-reviews']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/reservations/me']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/reservations/{reservationId}/reviews']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/tours/{tourId}/reviews']").exists())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(document)
                .doesNotContain("providerTokenEncrypted")
                .doesNotContain("providerCustomerKeyEncrypted")
                .doesNotContain("providerCardTokenEncrypted")
                .doesNotContain("ibanEncrypted")
                .doesNotContain("dataProtectionKey");
    }
}
