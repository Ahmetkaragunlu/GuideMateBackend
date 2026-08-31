package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Timestamp;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:tc:postgresql:18-alpine:///guidemate_demo_api_contract_test",
        "spring.task.scheduling.enabled=false",
        "scheduler.reservation-delay-ms=3600000",
        "scheduler.payment-delay-ms=3600000",
        "scheduler.refund-delay-ms=3600000",
        "scheduler.earning-delay-ms=3600000",
        "scheduler.notification-delay-ms=3600000",
        "scheduler.reminder-delay-ms=3600000",
        "scheduler.device-cleanup-delay-ms=3600000"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(DemoApiContractIntegrationTest.FixedClockConfig.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DemoApiContractIntegrationTest {

    private static final long LEGENDARY_GUIDE_ID = 2050L;

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private DemoDatasetWriter datasetWriter;
    @Autowired
    private DemoDatasetVerifier datasetVerifier;
    @Autowired
    private DemoBankFixtures bankFixtures;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private TransactionTemplate transactionTemplate;

    @BeforeAll
    void seedIsolatedApiDatabase() {
        datasetVerifier.requireEmptyTarget();
        transactionTemplate.executeWithoutResult(status -> datasetWriter.write(
                passwordEncoder.encode(DemoTestFixtures.PASSWORD),
                DemoTestFixtures.REFERENCE_INSTANT,
                DemoTestFixtures.mediaFixtures(),
                bankFixtures.create()
        ));
        datasetVerifier.verify(DemoTestFixtures.REFERENCE_INSTANT);
    }

    @Test
    void exposesDiscoveryFiltersPaginationAndCanonicalCapacity() throws Exception {
        Map<String, Object> filter = jdbcTemplate.queryForMap("""
                select tour.country_code, tour.category_code
                from tours tour
                join tour_sessions session on session.tour_id = tour.id
                where tour.approval_status = 'APPROVED'
                  and session.status = 'OPEN_FOR_BOOKING'
                  and session.starts_at > ?
                group by tour.country_code, tour.category_code
                having count(*) > 3
                order by count(*) desc, tour.country_code, tour.category_code
                limit 1
                """, Timestamp.from(DemoTestFixtures.REFERENCE_INSTANT));

        MvcResult firstPageResult = mockMvc.perform(get("/api/v1/tours/search")
                        .param("countryCode", filter.get("country_code").toString())
                        .param("categoryCode", filter.get("category_code").toString())
                        .param("page", "0")
                        .param("size", "3")
                        .param("sort", "PRICE_ASC"))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode firstPage = json(firstPageResult);

        assertThat(firstPage.path("content").size()).isEqualTo(3);
        assertThat(firstPage.path("page").asInt()).isZero();
        assertThat(firstPage.path("size").asInt()).isEqualTo(3);
        assertThat(firstPage.path("totalElements").asLong()).isGreaterThan(3);
        assertThat(firstPage.path("first").asBoolean()).isTrue();
        firstPage.path("content").forEach(item -> {
            assertThat(item.path("countryCode").asText())
                    .isEqualTo(filter.get("country_code").toString());
            assertThat(item.path("categoryCode").asText())
                    .isEqualTo(filter.get("category_code").toString());
            assertThat(item.path("availableCapacity").asInt()).isPositive();
        });

        mockMvc.perform(get("/api/v1/tours/search")
                        .param("countryCode", filter.get("country_code").toString())
                        .param("categoryCode", filter.get("category_code").toString())
                        .param("page", "1")
                        .param("size", "3"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.first").value(false));

        UUID tourId = UUID.fromString(firstPage.path("content").get(0).path("tourId").asText());
        UUID sessionId = UUID.fromString(firstPage.path("content").get(0).path("sessionId").asText());
        Map<String, Object> expectedSession = jdbcTemplate.queryForMap("""
                select session.capacity,
                       coalesce(sum(reservation.participant_count) filter (
                           where reservation.status in ('CONFIRMED', 'COMPLETED')
                              or (reservation.status = 'PENDING_PAYMENT'
                                  and reservation.hold_expires_at > ?)
                       ), 0) as booked_count
                from tour_sessions session
                left join reservations reservation on reservation.session_id = session.id
                where session.id = ?
                group by session.id
                """, Timestamp.from(DemoTestFixtures.REFERENCE_INSTANT), sessionId);

        mockMvc.perform(get("/api/v1/tour-sessions/{sessionId}", sessionId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sessions[0].capacity").value(expectedSession.get("capacity")))
                .andExpect(jsonPath("$.sessions[0].bookedCount").value(expectedSession.get("booked_count")))
                .andExpect(jsonPath("$.sessions[0].availableCapacity").value(
                        ((Number) expectedSession.get("capacity")).intValue()
                                - ((Number) expectedSession.get("booked_count")).intValue()
                ));
        mockMvc.perform(get("/api/v1/tours/{tourId}", tourId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tourId").value(tourId.toString()))
                .andExpect(jsonPath("$.cover.mediaAssetId").isNotEmpty())
                .andExpect(jsonPath("$.guide.avatar.mediaAssetId").isNotEmpty());
    }

    @Test
    void exposesCalculatedWalletReservationNotificationAndGuideProjections() throws Exception {
        String touristToken = login("tourist233@demo.guidemate.test");

        mockMvc.perform(get("/api/v1/wallet").header("Authorization", bearer(touristToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.balanceMinor").value(12_500))
                .andExpect(jsonPath("$.currencyCode").value("USD"));
        mockMvc.perform(get("/api/v1/reservations/me")
                        .header("Authorization", bearer(touristToken))
                        .param("status", "PAST")
                        .param("page", "0")
                        .param("size", "5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(5))
                .andExpect(jsonPath("$.totalElements").value(21))
                .andExpect(jsonPath("$.totalPages").value(5));
        mockMvc.perform(get("/api/v1/notifications")
                        .header("Authorization", bearer(touristToken))
                        .param("page", "0")
                        .param("size", "5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(5))
                .andExpect(jsonPath("$.totalElements").value(19))
                .andExpect(jsonPath("$.last").value(false));

        String guideToken = login("guide050@demo.guidemate.test");
        mockMvc.perform(get("/api/v1/guides/{guideId}/public-profile", LEGENDARY_GUIDE_ID))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.performance.completedSessionCount").value(100))
                .andExpect(jsonPath("$.performance.totalParticipantCount").value(716))
                .andExpect(jsonPath("$.performance.averageRating").value(4.96))
                .andExpect(jsonPath("$.performance.reviewCount").value(50))
                .andExpect(jsonPath("$.performance.level").value("LEGENDARY"));
        mockMvc.perform(get("/api/v1/guides/me/dashboard")
                        .header("Authorization", bearer(guideToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.completedSessionCount").value(100))
                .andExpect(jsonPath("$.reviewCount").value(50))
                .andExpect(jsonPath("$.level").value("LEGENDARY"));

        JsonNode monthly = json(mockMvc.perform(get("/api/v1/guide/earnings/monthly")
                        .header("Authorization", bearer(guideToken))
                        .param("year", "2026"))
                .andExpect(status().isOk())
                .andReturn());
        assertThat(monthly.size()).isEqualTo(5);
        assertMonthlyEarning(monthly.get(0), 2026, 8, 114_300L);
        assertMonthlyEarning(monthly.get(1), 2026, 7, 1_477_350L);
        assertMonthlyEarning(monthly.get(2), 2026, 6, 5_295_600L);
        assertMonthlyEarning(monthly.get(3), 2026, 5, 2_455_200L);
        assertMonthlyEarning(monthly.get(4), 2026, 4, 1_324_350L);
    }

    @Test
    void exposesChatCursorPaginationWithoutLeakingConversations() throws Exception {
        String participantToken = login("tourist028@demo.guidemate.test");
        JsonNode conversations = json(mockMvc.perform(get("/api/v1/chats")
                        .header("Authorization", bearer(participantToken)))
                .andExpect(status().isOk())
                .andReturn());
        assertThat(conversations.size()).isEqualTo(1);
        String chatId = conversations.get(0).path("chatId").asText();

        JsonNode firstPage = json(mockMvc.perform(get("/api/v1/chats/{chatId}/messages", chatId)
                        .header("Authorization", bearer(participantToken))
                        .param("size", "50"))
                .andExpect(status().isOk())
                .andReturn());
        assertThat(firstPage.path("content").size()).isEqualTo(50);
        assertThat(firstPage.path("hasNext").asBoolean()).isTrue();
        assertThat(firstPage.path("nextCursor").asText()).isNotBlank();

        JsonNode secondPage = json(mockMvc.perform(get("/api/v1/chats/{chatId}/messages", chatId)
                        .header("Authorization", bearer(participantToken))
                        .param("size", "50")
                        .param("before", firstPage.path("nextCursor").asText()))
                .andExpect(status().isOk())
                .andReturn());
        assertThat(secondPage.path("content").size()).isEqualTo(10);
        assertThat(secondPage.path("hasNext").asBoolean()).isFalse();

        String outsiderToken = login("tourist001@demo.guidemate.test");
        mockMvc.perform(get("/api/v1/chats/{chatId}/messages", chatId)
                        .header("Authorization", bearer(outsiderToken)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("CHAT_NOT_FOUND"));
    }

    @Test
    void enforcesAuthRoleOwnershipAndPublishesTheCompleteOpenApiContract() throws Exception {
        mockMvc.perform(get("/api/v1/chats"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
        expectLoginFailure(
                "pending.valid@demo.guidemate.test",
                "ACCOUNT_PENDING_VERIFICATION"
        );
        expectLoginFailure("disabled.tourist@demo.guidemate.test", "ACCOUNT_DISABLED");

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Installation-Id", UUID.randomUUID().toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody("role.selection@demo.guidemate.test")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roleSelected").value(false))
                .andExpect(jsonPath("$.role").doesNotExist());

        String touristToken = login("tourist001@demo.guidemate.test");
        mockMvc.perform(get("/api/v1/guides/me/dashboard")
                        .header("Authorization", bearer(touristToken)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        UUID anotherTouristReservation = jdbcTemplate.queryForObject("""
                select id from reservations where tourist_id = 1061 order by created_at limit 1
                """, UUID.class);
        mockMvc.perform(get("/api/v1/reservations/{reservationId}", anotherTouristReservation)
                        .header("Authorization", bearer(touristToken)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("RESERVATION_NOT_FOUND"));

        String guideToken = login("guide001@demo.guidemate.test");
        mockMvc.perform(get("/api/v1/reservations/me")
                        .header("Authorization", bearer(guideToken)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        String adminToken = login("admin@demo.guidemate.test");
        mockMvc.perform(get("/api/v1/admin/tour-reviews")
                        .header("Authorization", bearer(adminToken))
                        .param("page", "0")
                        .param("size", "10"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()").value(10))
                .andExpect(jsonPath("$.totalElements").value(30));

        JsonNode openApi = json(mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andReturn());
        JsonNode paths = openApi.path("paths");
        assertThat(paths.has("/api/v1/tours/search")).isTrue();
        assertThat(paths.has("/api/v1/reservations/me")).isTrue();
        assertThat(paths.has("/api/v1/guide/earnings/monthly")).isTrue();
        assertThat(paths.has("/api/v1/chats/{chatId}/messages")).isTrue();
        assertThat(paths.has("/api/v1/notifications")).isTrue();
        assertThat(paths.has("/api/v1/users/me/avatar")).isTrue();
        assertThat(paths.has("/api/v1/payments/checkout/tour")).isTrue();
        assertThat(paths.has("/api/v1/payments/iyzico/webhook")).isFalse();
    }

    private String login(String email) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Installation-Id", UUID.randomUUID().toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(email)))
                .andExpect(status().isOk())
                .andReturn();
        return json(result).path("accessToken").asText();
    }

    private void expectLoginFailure(String email, String code) throws Exception {
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Installation-Id", UUID.randomUUID().toString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(email)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value(code));
    }

    private String loginBody(String email) throws Exception {
        return objectMapper.writeValueAsString(Map.of(
                "email", email,
                "password", DemoTestFixtures.PASSWORD
        ));
    }

    private JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsByteArray());
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }

    private void assertMonthlyEarning(JsonNode item, int year, int month, long netEarningsMinor) {
        assertThat(item.path("year").asInt()).isEqualTo(year);
        assertThat(item.path("month").asInt()).isEqualTo(month);
        assertThat(item.path("netEarningsMinor").asLong()).isEqualTo(netEarningsMinor);
        assertThat(item.path("currencyCode").asText()).isEqualTo("USD");
    }

    @TestConfiguration
    static class FixedClockConfig {

        @Bean
        @Primary
        Clock demoApiClock() {
            return Clock.fixed(DemoTestFixtures.REFERENCE_INSTANT, ZoneOffset.UTC);
        }
    }
}
