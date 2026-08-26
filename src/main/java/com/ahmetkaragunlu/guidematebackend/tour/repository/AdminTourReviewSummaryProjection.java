package com.ahmetkaragunlu.guidematebackend.tour.repository;

import java.time.Instant;
import java.util.UUID;

public interface AdminTourReviewSummaryProjection {

    UUID getReviewId();

    String getReviewType();

    UUID getTourId();

    Long getGuideId();

    String getGuideDisplayName();

    String getTitle();

    Instant getSubmittedAt();
}
