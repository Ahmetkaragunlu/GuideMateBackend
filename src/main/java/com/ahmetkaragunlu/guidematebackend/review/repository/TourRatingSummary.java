package com.ahmetkaragunlu.guidematebackend.review.repository;

import java.util.UUID;

public interface TourRatingSummary {

    UUID getTourId();

    double getAverageRating();

    long getReviewCount();
}
