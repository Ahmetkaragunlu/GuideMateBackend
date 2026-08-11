package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPreference;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.dto.NotificationPreferenceResponse;
import com.ahmetkaragunlu.guidematebackend.notification.dto.UpdateNotificationPreferenceRequest;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationPreferenceRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class NotificationPreferenceService {

    private final NotificationPreferenceRepository preferenceRepository;
    private final UserRepository userRepository;

    @Transactional
    public NotificationPreferenceResponse get(User currentUser) {
        return toResponse(getOrCreate(currentUser.getId()));
    }

    @Transactional
    public NotificationPreferenceResponse update(
            User currentUser,
            UpdateNotificationPreferenceRequest request
    ) {
        NotificationPreference preference = getOrCreate(currentUser.getId());
        preference.update(
                request.upcomingTourRemindersEnabled(),
                request.chatMessagesEnabled(),
                request.reservationUpdatesEnabled(),
                request.reviewRequestsEnabled(),
                request.paymentsAndEarningsEnabled(),
                request.newReviewsEnabled()
        );
        return toResponse(preference);
    }

    @Transactional(readOnly = true)
    public boolean isPushEnabled(Long userId, NotificationType type) {
        NotificationPreference preference = preferenceRepository.findById(userId).orElse(null);
        if (preference == null || type == NotificationType.SECURITY_ALERT) {
            return true;
        }
        return switch (type) {
            case UPCOMING_TOUR_REMINDER -> preference.isUpcomingTourRemindersEnabled();
            case CHAT_MESSAGE -> preference.isChatMessagesEnabled();
            case REVIEW_REQUEST -> preference.isReviewRequestsEnabled();
            case PAYMENT_SUCCEEDED, PAYMENT_FAILED, REFUND_REQUESTED, REFUND_COMPLETED,
                    REFUND_FAILED, REFUND_MANUAL_REVIEW, EARNING_AVAILABLE,
                    WITHDRAWAL_COMPLETED -> preference.isPaymentsAndEarningsEnabled();
            case RATING_RECEIVED, COMMENT_RECEIVED -> preference.isNewReviewsEnabled();
            default -> preference.isReservationUpdatesEnabled();
        };
    }

    private NotificationPreference getOrCreate(Long userId) {
        return preferenceRepository.findById(userId)
                .orElseGet(() -> preferenceRepository.save(
                        new NotificationPreference(userRepository.getReferenceById(userId))
                ));
    }

    private NotificationPreferenceResponse toResponse(NotificationPreference preference) {
        return new NotificationPreferenceResponse(
                preference.isUpcomingTourRemindersEnabled(),
                preference.isChatMessagesEnabled(),
                preference.isReservationUpdatesEnabled(),
                preference.isReviewRequestsEnabled(),
                preference.isPaymentsAndEarningsEnabled(),
                preference.isNewReviewsEnabled(),
                true
        );
    }
}
