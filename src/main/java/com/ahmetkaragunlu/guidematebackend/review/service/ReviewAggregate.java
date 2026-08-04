package com.ahmetkaragunlu.guidematebackend.review.service;

public record ReviewAggregate(
        double averageRating,
        long reviewCount
) {

    public static final ReviewAggregate EMPTY = new ReviewAggregate(0.0, 0);
}
