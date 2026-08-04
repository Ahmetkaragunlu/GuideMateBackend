package com.ahmetkaragunlu.guidematebackend.review.repository;

public interface GuideRatingSummary {

    Long getGuideId();

    double getAverageRating();

    long getReviewCount();
}
