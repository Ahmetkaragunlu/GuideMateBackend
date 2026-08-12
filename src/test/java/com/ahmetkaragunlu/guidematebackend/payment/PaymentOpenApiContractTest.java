package com.ahmetkaragunlu.guidematebackend.payment;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class PaymentOpenApiContractTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publishesPaymentWalletAndGuideFinanceContracts() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/payments/checkout/tour']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payments/checkout/tour/quote']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payments/checkout/wallet-top-up']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payments/checkout/wallet-top-up/quote']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payments/checkout/currencies']").exists())
                .andExpect(jsonPath("$.components.schemas.PaymentQuoteResponse.properties.baseAmountMinor").exists())
                .andExpect(jsonPath("$.components.schemas.PaymentQuoteResponse.properties.chargeAmountMinor").exists())
                .andExpect(jsonPath("$.components.schemas.PaymentResponse.properties.chargeCurrencyCode").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payments/{paymentId}']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payments/{paymentId}/cancel']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payment-methods/cards']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payment-methods/cards/{savedPaymentMethodId}']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/payment-methods/cards/{savedPaymentMethodId}/default']").exists())
                .andExpect(jsonPath("$.components.schemas.SavedPaymentMethodResponse.properties.cardToken")
                        .doesNotExist())
                .andExpect(jsonPath("$.components.schemas.SavedPaymentMethodResponse.properties.customerKey")
                        .doesNotExist())
                .andExpect(jsonPath("$.components.schemas.SavedPaymentMethodResponse.properties.cardNumber")
                        .doesNotExist())
                .andExpect(jsonPath("$.components.schemas.SavedPaymentMethodResponse.properties.cvc")
                        .doesNotExist())
                .andExpect(jsonPath("$.paths['/api/v1/wallet']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/wallet/transactions']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/guide/earnings']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/guide/bank-accounts']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/guide/bank-accounts/{bankAccountId}/default']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/guide/withdrawals']").exists());
    }
}
