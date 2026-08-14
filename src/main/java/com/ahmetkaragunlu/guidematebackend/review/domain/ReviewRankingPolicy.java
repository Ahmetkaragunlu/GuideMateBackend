package com.ahmetkaragunlu.guidematebackend.review.domain;

import org.springframework.stereotype.Component;

@Component
public class ReviewRankingPolicy {

    public static final double PRIOR_RATING = 3.5;
    public static final double PRIOR_WEIGHT = 5.0;

    public double weightedScore(double averageRating, long reviewCount) {
        return (averageRating * reviewCount + PRIOR_RATING * PRIOR_WEIGHT)
                / (reviewCount + PRIOR_WEIGHT);
    }
}
