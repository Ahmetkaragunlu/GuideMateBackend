package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentFxQuote;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ExchangeRate;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ExchangeRateProvider;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.PayoutMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentQuoteServiceTest {

    @Mock
    private ReservationBookingService reservationBookingService;
    @Mock
    private PaymentQuoteStateService stateService;
    @Mock
    private ExchangeRateProvider exchangeRateProvider;
    @Mock
    private PaymentFxQuote savedQuote;
    @Mock
    private User tourist;
    @Mock
    private Role touristRole;

    private PaymentQuoteService service;

    @BeforeEach
    void setUp() {
        when(tourist.getRole()).thenReturn(touristRole);
        when(touristRole.getName()).thenReturn(RoleType.ROLE_TOURIST.name());
        service = new PaymentQuoteService(
                reservationBookingService,
                stateService,
                exchangeRateProvider,
                paymentProperties(),
                Clock.fixed(Instant.parse("2026-08-13T00:00:00Z"), ZoneOffset.UTC)
        );
    }

    @Test
    void convertsCanonicalUsdToChargeMinorUnitsWithCentralRounding() {
        when(exchangeRateProvider.latest("USD", "EUR")).thenReturn(new ExchangeRate(
                "USD",
                "EUR",
                new BigDecimal("1.23456"),
                "FRANKFURTER_ECB",
                LocalDate.of(2026, 8, 12)
        ));
        when(stateService.saveWalletTopUpQuote(eq(tourist), eq(1000L), any(FxCalculation.class)))
                .thenReturn(savedQuote);

        service.quoteWalletTopUp(tourist, 1000L, "eur");

        ArgumentCaptor<FxCalculation> calculation = ArgumentCaptor.forClass(FxCalculation.class);
        verify(stateService).saveWalletTopUpQuote(eq(tourist), eq(1000L), calculation.capture());
        assertThat(calculation.getValue().chargeAmountMinor()).isEqualTo(1235L);
        assertThat(calculation.getValue().chargeCurrencyCode()).isEqualTo("EUR");
        assertThat(calculation.getValue().rate()).isEqualByComparingTo("1.234560000000");
    }

    @Test
    void rejectsCurrencyOutsideConfiguredProviderSubset() {
        assertThatThrownBy(() -> service.quoteWalletTopUp(tourist, 1000L, "JPY"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_CURRENCY_NOT_SUPPORTED));

        verify(exchangeRateProvider, never()).latest(any(), any());
        verify(stateService, never()).saveWalletTopUpQuote(any(), any(Long.class), any());
    }

    private PaymentProperties paymentProperties() {
        return new PaymentProperties(
                "USD",
                Duration.ofMinutes(30),
                "https://example.test",
                new PaymentProperties.Fx(
                        URI.create("https://api.frankfurter.dev"),
                        Duration.ofMinutes(10),
                        Duration.ofSeconds(3),
                        Duration.ofSeconds(5),
                        Set.of("USD", "TRY", "EUR", "GBP"),
                        "ECB"
                ),
                new PaymentProperties.Iyzico(
                        "test-api-key",
                        "test-secret-key",
                        "https://sandbox-api.iyzipay.com"
                ),
                PayoutMode.SIMULATED,
                1000,
                new PaymentProperties.SandboxBuyer(
                        false,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null
                )
        );
    }
}
