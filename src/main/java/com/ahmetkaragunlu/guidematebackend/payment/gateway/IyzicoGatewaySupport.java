package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import java.util.function.Supplier;

final class IyzicoGatewaySupport {

    private IyzicoGatewaySupport() {
    }

    static <T> T execute(Supplier<T> operation) {
        try {
            return operation.get();
        } catch (PaymentGatewayException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new PaymentGatewayException("PROVIDER_UNAVAILABLE", exception);
        }
    }

    static void execute(Runnable operation) {
        execute(() -> {
            operation.run();
            return null;
        });
    }

    static String normalizeFailureCode(String value) {
        return value == null || value.isBlank() ? "PROVIDER_REJECTED" : value.trim();
    }
}
