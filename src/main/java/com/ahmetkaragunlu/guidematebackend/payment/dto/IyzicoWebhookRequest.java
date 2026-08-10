package com.ahmetkaragunlu.guidematebackend.payment.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record IyzicoWebhookRequest(
        @JsonProperty("iyziEventType") String eventType,
        @JsonProperty("iyziEventTime") String eventTime,
        @JsonProperty("iyziPaymentId") String paymentId,
        String token,
        @JsonProperty("paymentConversationId") String conversationId,
        String status
) {
    public String eventSeed() {
        return String.join("|",
                value(eventType),
                value(eventTime),
                value(paymentId),
                value(token),
                value(conversationId),
                value(status)
        );
    }

    public String value(String input) {
        return input == null ? "" : input;
    }
}
