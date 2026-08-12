package com.ahmetkaragunlu.guidematebackend.payment.config;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.PayoutMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;

@ConfigurationProperties(prefix = "payment")
public record PaymentProperties(
        String canonicalCurrencyCode,
        Duration checkoutExpiration,
        String callbackBaseUrl,
        Fx fx,
        Iyzico iyzico,
        PayoutMode payoutMode,
        int platformCommissionBasisPoints,
        SandboxBuyer sandboxBuyer
) {

    public PaymentProperties {
        if (!"USD".equals(canonicalCurrencyCode)) {
            throw new IllegalArgumentException("payment.canonical-currency-code must be USD");
        }
        if (checkoutExpiration == null || checkoutExpiration.isZero() || checkoutExpiration.isNegative()) {
            throw new IllegalArgumentException("payment.checkout-expiration must be positive");
        }
        if (fx == null || iyzico == null || payoutMode == null || sandboxBuyer == null) {
            throw new IllegalArgumentException("Payment provider configuration is incomplete");
        }
        if (platformCommissionBasisPoints != 1000) {
            throw new IllegalArgumentException("GuideMate platform commission must be 10 percent");
        }
    }

    public record Fx(
            URI baseUrl,
            Duration quoteTtl,
            Duration connectTimeout,
            Duration readTimeout,
            Set<String> enabledChargeCurrencies,
            String rateProvider
    ) {
        private static final Set<String> IYZICO_CURRENCIES = Set.of(
                "USD", "TRY", "EUR", "GBP", "NOK", "CHF"
        );

        public Fx {
            if (baseUrl == null
                    || !"https".equalsIgnoreCase(baseUrl.getScheme())
                    || baseUrl.getHost() == null) {
                throw new IllegalArgumentException("payment.fx.base-url must be HTTPS");
            }
            if (quoteTtl == null || quoteTtl.isZero() || quoteTtl.isNegative()
                    || connectTimeout == null || connectTimeout.isZero() || connectTimeout.isNegative()
                    || readTimeout == null || readTimeout.isZero() || readTimeout.isNegative()) {
                throw new IllegalArgumentException("Payment FX durations must be positive");
            }
            if (enabledChargeCurrencies == null || enabledChargeCurrencies.isEmpty()) {
                throw new IllegalArgumentException("At least one charge currency must be enabled");
            }
            enabledChargeCurrencies = enabledChargeCurrencies.stream()
                    .map(code -> code.trim().toUpperCase(Locale.ROOT))
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (!enabledChargeCurrencies.contains("USD")
                    || !IYZICO_CURRENCIES.containsAll(enabledChargeCurrencies)) {
                throw new IllegalArgumentException("Enabled charge currencies must include USD and be supported by iyzico");
            }
            if (isBlank(rateProvider)) {
                throw new IllegalArgumentException("payment.fx.rate-provider is required");
            }
            rateProvider = rateProvider.trim().toUpperCase(Locale.ROOT);
        }
    }

    public URI callbackUri(String path) {
        if (callbackBaseUrl == null || callbackBaseUrl.isBlank()) {
            throw new IllegalStateException("PAYMENT_CALLBACK_BASE_URL is required for hosted checkout");
        }
        URI baseUri = URI.create(callbackBaseUrl.trim());
        if (!"https".equalsIgnoreCase(baseUri.getScheme()) || baseUri.getHost() == null) {
            throw new IllegalStateException("PAYMENT_CALLBACK_BASE_URL must be a public HTTPS URL");
        }
        return URI.create(callbackBaseUrl.replaceAll("/+$", "") + path);
    }

    public record Iyzico(String apiKey, String secretKey, String baseUrl) {
        public Iyzico {
            if (isBlank(apiKey) || isBlank(secretKey) || isBlank(baseUrl)) {
                throw new IllegalArgumentException("Iyzico API key, secret key and base URL are required");
            }
            URI uri = URI.create(baseUrl);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
                throw new IllegalArgumentException("payment.iyzico.base-url must be HTTPS");
            }
        }
    }

    public record SandboxBuyer(
            boolean enabled,
            String identityNumber,
            String phoneNumber,
            String address,
            String city,
            String country,
            String zipCode,
            String ipAddress
    ) {
        public SandboxBuyer {
            if (enabled && (isBlank(identityNumber)
                    || isBlank(phoneNumber)
                    || isBlank(address)
                    || isBlank(city)
                    || isBlank(country)
                    || isBlank(zipCode)
                    || isBlank(ipAddress))) {
                throw new IllegalArgumentException("Sandbox buyer configuration is incomplete");
            }
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
