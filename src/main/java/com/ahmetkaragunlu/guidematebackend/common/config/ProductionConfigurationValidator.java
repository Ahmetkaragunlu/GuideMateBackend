package com.ahmetkaragunlu.guidematebackend.common.config;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.Locale;
import java.util.Set;

@Component
@Profile("prod")
public class ProductionConfigurationValidator {

    private static final Set<String> LOCAL_HOSTS = Set.of("localhost", "127.0.0.1", "10.0.2.2");

    private final AppProperties appProperties;
    private final PaymentProperties paymentProperties;

    public ProductionConfigurationValidator(
            AppProperties appProperties,
            PaymentProperties paymentProperties
    ) {
        this.appProperties = appProperties;
        this.paymentProperties = paymentProperties;
    }

    @PostConstruct
    void validate() {
        requirePublicHttps(appProperties.publicBaseUrl(), "PUBLIC_BASE_URL");
        String callbackBaseUrl = paymentProperties.callbackBaseUrl();
        if (callbackBaseUrl == null || callbackBaseUrl.isBlank()) {
            throw invalidPublicUrl("PAYMENT_CALLBACK_BASE_URL");
        }
        try {
            requirePublicHttps(URI.create(callbackBaseUrl.trim()), "PAYMENT_CALLBACK_BASE_URL");
        } catch (IllegalArgumentException exception) {
            throw invalidPublicUrl("PAYMENT_CALLBACK_BASE_URL");
        }
    }

    private void requirePublicHttps(URI uri, String propertyName) {
        String host = uri.getHost() == null ? null : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || host == null
                || LOCAL_HOSTS.contains(host)
                || isPrivateHost(host)) {
            throw invalidPublicUrl(propertyName);
        }
    }

    private IllegalStateException invalidPublicUrl(String propertyName) {
        return new IllegalStateException("Production " + propertyName + " must be a public HTTPS URL");
    }

    private boolean isPrivateHost(String host) {
        if (host.endsWith(".local")
                || host.startsWith("10.")
                || host.startsWith("192.168.")
                || host.startsWith("169.254.")
                || "::1".equals(host)) {
            return true;
        }

        if (!host.startsWith("172.")) {
            return false;
        }
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        try {
            int secondOctet = Integer.parseInt(parts[1]);
            return secondOctet >= 16 && secondOctet <= 31;
        } catch (NumberFormatException exception) {
            return false;
        }
    }
}
