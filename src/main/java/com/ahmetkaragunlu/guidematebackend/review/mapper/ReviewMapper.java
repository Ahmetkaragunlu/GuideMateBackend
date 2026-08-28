package com.ahmetkaragunlu.guidematebackend.review.mapper;

import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.dto.TourReviewResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ReviewMapper {

    private final MediaReferenceMapper mediaReferenceMapper;

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
                mediaReferenceMapper.fromId(tourist.getAvatarMediaId()),
                review.getRating(),
                review.getComment(),
                review.getCreatedAt()
        );
    }
}
