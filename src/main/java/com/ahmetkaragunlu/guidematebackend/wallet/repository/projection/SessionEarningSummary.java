package com.ahmetkaragunlu.guidematebackend.wallet.repository.projection;

import java.util.UUID;

public interface SessionEarningSummary {

    UUID getSessionId();

    Long getNetEarningsMinor();
}
