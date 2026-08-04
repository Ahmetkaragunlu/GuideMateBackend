package com.ahmetkaragunlu.guidematebackend.review.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
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
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ReviewService {

    private final ReservationRepository reservationRepository;
    private final ReviewRepository reviewRepository;
    private final ReviewMapper reviewMapper;
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
        try {
            return reviewMapper.toResponse(reviewRepository.saveAndFlush(review));
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.REVIEW_ALREADY_EXISTS, exception);
        }
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }
}
