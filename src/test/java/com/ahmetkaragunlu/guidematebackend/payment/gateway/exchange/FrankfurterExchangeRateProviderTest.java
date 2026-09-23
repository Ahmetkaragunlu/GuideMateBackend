package com.ahmetkaragunlu.guidematebackend.payment.gateway.exchange;

import com.ahmetkaragunlu.guidematebackend.support.TestPaymentProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.math.BigDecimal;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class FrankfurterExchangeRateProviderTest {

    private MockRestServiceServer server;
    private FrankfurterExchangeRateProvider provider;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder().baseUrl("https://api.frankfurter.dev");
        server = MockRestServiceServer.bindTo(builder).build();
        provider = new FrankfurterExchangeRateProvider(builder.build(), TestPaymentProperties.defaults());
    }

    @Test
    void returnsValidatedProviderRate() {
        server.expect(requestTo("https://api.frankfurter.dev/v2/rate/USD/TRY?providers=ECB"))
                .andRespond(withSuccess(
                        """
                                {"date":"2026-09-24","base":"USD","quote":"TRY","rate":41.25}
                                """,
                        MediaType.APPLICATION_JSON
                ));

        ExchangeRate rate = provider.latest("USD", "TRY");

        assertThat(rate.rate()).isEqualByComparingTo(new BigDecimal("41.25"));
        assertThat(rate.rateDate()).isEqualTo(LocalDate.of(2026, 9, 24));
        assertThat(rate.source()).isEqualTo("FRANKFURTER_ECB");
        server.verify();
    }

    @Test
    void rejectsMismatchedOrNonPositiveProviderResponse() {
        server.expect(requestTo("https://api.frankfurter.dev/v2/rate/USD/TRY?providers=ECB"))
                .andRespond(withSuccess(
                        """
                                {"date":"2026-09-24","base":"EUR","quote":"TRY","rate":0}
                                """,
                        MediaType.APPLICATION_JSON
                ));

        assertThatThrownBy(() -> provider.latest("USD", "TRY"))
                .isInstanceOf(ExchangeRateUnavailableException.class);
        server.verify();
    }
}
