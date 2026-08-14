package com.ahmetkaragunlu.guidematebackend.review.mapper;

import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.dto.TourReviewResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.springframework.stereotype.Component;

@Component
public class ReviewMapper {

    public ReviewResponse toResponse(Review review) {
        return new ReviewResponse(
                review.getId(),
                review.getRating(),
                review.getComment(),
                review.getCreatedAt()
        );
    }

    public TourReviewResponse toPublicResponse(Review review) {
        User tourist = review.getReservation().getTourist();
        return new TourReviewResponse(
                review.getId(),
                tourist.displayName(),
                null,
                review.getRating(),
                review.getComment(),
                review.getCreatedAt()
        );
    }
}
