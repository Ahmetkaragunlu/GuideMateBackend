package com.ahmetkaragunlu.guidematebackend.payment.service;

import java.util.UUID;

public record RefundRequestedEvent(UUID refundId) {
}
