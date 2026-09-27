package com.ahmetkaragunlu.guidematebackend.wallet.dto.response;

import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarningStatus;

import java.time.Instant;
import java.util.UUID;

public record GuideEarningResponse(
        UUID earningId,
        UUID reservationId,
        long grossMinor,
        long platformFeeMinor,
        long netMinor,
        String currencyCode,
        GuideEarningStatus status,
        Instant availableAt,
        Instant createdAt
) {
}
