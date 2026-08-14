package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentFxQuote;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ExchangeRate;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ExchangeRateProvider;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
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
    private PaymentQuoteService service;

    @BeforeEach
    void setUp() {
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
        stubTourist();
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
        stubTourist();
        assertThatThrownBy(() -> service.quoteWalletTopUp(tourist, 1000L, "JPY"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_CURRENCY_NOT_SUPPORTED));

        verify(exchangeRateProvider, never()).latest(any(), any());
        verify(stateService, never()).saveWalletTopUpQuote(any(), any(Long.class), any());
    }

    @Test
    void exposesCanonicalAndEnabledChargeCurrencies() {
        assertThat(service.getCurrencyOptions().baseCurrencyCode()).isEqualTo("USD");
        assertThat(service.getCurrencyOptions().chargeCurrencies())
                .extracting(option -> option.currencyCode())
                .containsExactly("EUR", "GBP", "TRY", "USD");
    }

    @Test
    void usesIdentityRateForCanonicalUsdWithoutCallingExternalProvider() {
        stubTourist();
        when(stateService.saveWalletTopUpQuote(eq(tourist), eq(1000L), any(FxCalculation.class)))
                .thenReturn(savedQuote);

        service.quoteWalletTopUp(tourist, 1000L, "USD");

        ArgumentCaptor<FxCalculation> calculation = ArgumentCaptor.forClass(FxCalculation.class);
        verify(stateService).saveWalletTopUpQuote(eq(tourist), eq(1000L), calculation.capture());
        assertThat(calculation.getValue().chargeAmountMinor()).isEqualTo(1000L);
        assertThat(calculation.getValue().chargeCurrencyCode()).isEqualTo("USD");
        assertThat(calculation.getValue().rate()).isEqualByComparingTo("1.000000000000");
        verify(exchangeRateProvider, never()).latest(any(), any());
    }

    private void stubTourist() {
        when(tourist.hasRole(RoleType.ROLE_TOURIST)).thenReturn(true);
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
