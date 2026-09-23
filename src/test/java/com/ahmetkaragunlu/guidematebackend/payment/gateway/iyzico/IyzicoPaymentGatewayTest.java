package com.ahmetkaragunlu.guidematebackend.payment.gateway.iyzico;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.PaymentGatewayException;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.VerifiedPaymentResult;
import com.iyzipay.Options;
import com.iyzipay.model.CheckoutForm;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class IyzicoPaymentGatewayTest {

    private final Options options = paymentOptions();
    private final IyzicoPaymentGateway gateway = new IyzicoPaymentGateway(
            options,
            mock(PaymentProperties.class)
    );

    @Test
    void convertsVerifiedProviderDeclineToFailedResult() {
        CheckoutForm response = new CheckoutForm();
        response.setStatus("failure");
        response.setErrorCode("10051");
        response.setToken("checkout-token");
        response.setConversationId("conversation-id");
        response.setPaymentStatus("FAILURE");
        response.setPaidPrice(new BigDecimal("100.00"));
        response.setCurrency("TRY");

        VerifiedPaymentResult result = gateway.toVerifiedPaymentResult(response);

        assertThat(result.successful()).isFalse();
        assertThat(result.providerFailureCode()).isEqualTo("10051");
        assertThat(result.token()).isEqualTo("checkout-token");
        assertThat(result.conversationId()).isEqualTo("conversation-id");
        assertThat(result.providerStatus()).isEqualTo("FAILURE");
    }

    @Test
    void acceptsUnsignedProviderDeclineForCanonicalFailureProcessing() {
        CheckoutForm response = providerResponse("failure", "FAILURE", "10051");

        assertThatCode(() -> gateway.validateRetrieveResponseIntegrity(response))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsUnsignedProviderSuccess() {
        CheckoutForm response = providerResponse("success", "SUCCESS", null);

        assertThatThrownBy(() -> gateway.validateRetrieveResponseIntegrity(response))
                .isInstanceOf(PaymentGatewayException.class);
    }

    @Test
    void rejectsUnsignedAmbiguousProviderResponse() {
        CheckoutForm response = providerResponse("success", null, null);

        assertThatThrownBy(() -> gateway.validateRetrieveResponseIntegrity(response))
                .isInstanceOf(PaymentGatewayException.class);
    }

    @Test
    void rejectsProviderDeclineWithInvalidSignature() {
        CheckoutForm response = providerResponse("failure", "FAILURE", "10051");
        response.setSignature("invalid-signature");

        assertThatThrownBy(() -> gateway.validateRetrieveResponseIntegrity(response))
                .isInstanceOf(PaymentGatewayException.class);
    }

    private CheckoutForm providerResponse(String status, String paymentStatus, String errorCode) {
        CheckoutForm response = new CheckoutForm();
        response.setStatus(status);
        response.setPaymentStatus(paymentStatus);
        response.setErrorCode(errorCode);
        response.setToken("checkout-token");
        response.setConversationId("conversation-id");
        return response;
    }

    private static Options paymentOptions() {
        Options options = new Options();
        options.setSecretKey("test-secret-key");
        return options;
    }
}
