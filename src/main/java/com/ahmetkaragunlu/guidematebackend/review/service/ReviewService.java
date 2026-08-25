package com.ahmetkaragunlu.guidematebackend.review.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationCommand;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import com.ahmetkaragunlu.guidematebackend.review.dto.CreateReviewRequest;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.mapper.ReviewMapper;
import com.ahmetkaragunlu.guidematebackend.review.repository.ReviewRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReviewService {

    private final ReservationRepository reservationRepository;
    private final ReviewRepository reviewRepository;
    private final ReviewMapper reviewMapper;
    private final NotificationPublisher notificationPublisher;
    private final Clock clock;

    @Transactional
    public ReviewResponse submit(User currentUser, UUID reservationId, CreateReviewRequest request) {
        Reservation reservation = reservationRepository.findOwnedByIdForUpdate(
                        reservationId,
                        currentUser.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.RESERVATION_NOT_FOUND));
        if (reservation.getStatus() != ReservationStatus.COMPLETED
                || reservation.getSession().endsAt().isAfter(clock.instant())) {
            throw new BusinessException(ErrorCode.REVIEW_NOT_ALLOWED);
        }
        if (reviewRepository.existsByReservation_Id(reservationId)) {
            throw new BusinessException(ErrorCode.REVIEW_ALREADY_EXISTS);
        }

        Review review = Review.submit(reservation, request.rating(), trimToNull(request.comment()));
        Review savedReview;
        try {
            savedReview = reviewRepository.saveAndFlush(review);
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.REVIEW_ALREADY_EXISTS, exception);
        }
        publishGuideNotification(savedReview);
        return reviewMapper.toResponse(savedReview);
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private void publishGuideNotification(Review review) {
        Reservation reservation = review.getReservation();
        Map<String, Object> payload = new HashMap<>();
        payload.put("reviewId", review.getId().toString());
        payload.put("reservationId", reservation.getId().toString());
        payload.put("sessionId", reservation.getSession().getId().toString());
        payload.put("tourId", reservation.getSession().getTour().getId().toString());
        payload.put("tourTitle", reservation.getSession().getTour().getTitle());
        payload.put("rating", review.getRating());
        if (review.getComment() != null) {
            payload.put("commentPreview", review.getComment());
        }
        notificationPublisher.publish(new NotificationCommand(
                reservation.getSession().getTour().getGuide().getId(),
                review.getComment() == null
                        ? NotificationType.RATING_RECEIVED
                        : NotificationType.COMMENT_RECEIVED,
                reservation.getTourist().getId(),
                payload
        ));
    }
}
