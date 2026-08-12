package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentFxQuote;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentFxQuoteRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.PayoutMode;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PaymentQuoteStateServiceTest {

    @Test
    void rejectsExpiredQuoteBeforeHostedCheckout() {
        UUID quoteId = UUID.randomUUID();
        PaymentFxQuoteRepository quoteRepository = mock(PaymentFxQuoteRepository.class);
        PaymentFxQuote quote = mock(PaymentFxQuote.class);
        User user = mock(User.class);
        when(user.getId()).thenReturn(42L);
        when(quoteRepository.findByIdForUpdate(quoteId)).thenReturn(Optional.of(quote));
        when(quote.getUser()).thenReturn(user);
        when(quote.getPurpose()).thenReturn(PaymentPurpose.WALLET_TOP_UP);
        when(quote.isExpired(Instant.parse("2026-08-13T00:00:00Z"))).thenReturn(true);

        PaymentQuoteStateService service = new PaymentQuoteStateService(
                quoteRepository,
                mock(UserRepository.class),
                mock(TourSessionRepository.class),
                paymentProperties(),
                Clock.fixed(Instant.parse("2026-08-13T00:00:00Z"), ZoneOffset.UTC)
        );

        assertThatThrownBy(() -> service.requireWalletTopUpQuote(user, quoteId))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.FX_QUOTE_EXPIRED));
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
                new PaymentProperties.SandboxBuyer(false, null, null, null, null, null, null, null)
        );
    }
}
