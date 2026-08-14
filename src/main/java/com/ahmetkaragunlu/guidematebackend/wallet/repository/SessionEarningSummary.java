package com.ahmetkaragunlu.guidematebackend.wallet.repository;

import java.util.UUID;

public interface SessionEarningSummary {

    UUID getSessionId();

    Long getNetEarningsMinor();
}
