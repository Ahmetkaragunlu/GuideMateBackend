package com.ahmetkaragunlu.guidematebackend.payment.event;

import java.util.UUID;

public record RefundRequestedEvent(UUID refundId) {
}
