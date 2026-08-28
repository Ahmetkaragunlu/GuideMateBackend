package com.ahmetkaragunlu.guidematebackend.review.mapper;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.mapper.MediaReferenceMapper;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import com.ahmetkaragunlu.guidematebackend.review.dto.TourReviewResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReviewMapperTest {

    private final MediaReferenceMapper mediaReferenceMapper = mock(MediaReferenceMapper.class);
    private final ReviewMapper mapper = new ReviewMapper(mediaReferenceMapper);

    @Test
    void exposesTouristAvatarInPublicReviewProjection() {
        UUID avatarId = UUID.randomUUID();
        MediaReferenceResponse avatar = new MediaReferenceResponse(avatarId, "https://example.test/avatar");
        User tourist = mock(User.class);
        Reservation reservation = mock(Reservation.class);
        Review review = mock(Review.class);
        when(review.getReservation()).thenReturn(reservation);
        when(reservation.getTourist()).thenReturn(tourist);
        when(tourist.displayName()).thenReturn("Tourist User");
        when(tourist.getAvatarMediaId()).thenReturn(avatarId);
        when(mediaReferenceMapper.fromId(avatarId)).thenReturn(avatar);
        when(review.getId()).thenReturn(UUID.randomUUID());
        when(review.getRating()).thenReturn((short) 5);
        when(review.getComment()).thenReturn("Excellent tour");
        when(review.getCreatedAt()).thenReturn(Instant.parse("2026-08-27T10:00:00Z"));

        TourReviewResponse response = mapper.toPublicResponse(review);

        assertThat(response.reviewerDisplayName()).isEqualTo("Tourist User");
        assertThat(response.reviewerAvatar()).isEqualTo(avatar);
    }
}
