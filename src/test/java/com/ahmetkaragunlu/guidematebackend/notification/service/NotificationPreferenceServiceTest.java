package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPreference;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationType;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationPreferenceRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationPreferenceServiceTest {

    private static final long USER_ID = 42L;

    @Mock
    private NotificationPreferenceRepository preferenceRepository;

    @Mock
    private UserRepository userRepository;

    @Mock
    private User user;

    @InjectMocks
    private NotificationPreferenceService preferenceService;

    @Test
    void mapsEveryNotificationTypeToItsPreferenceCategory() {
        assertThat(enabledTypes(preference(false, false, false, false, false, false)))
                .containsExactly(NotificationType.SECURITY_ALERT);
        assertThat(enabledTypes(preference(true, false, false, false, false, false)))
                .containsExactlyInAnyOrder(NotificationType.UPCOMING_TOUR_REMINDER, NotificationType.SECURITY_ALERT);
        assertThat(enabledTypes(preference(false, true, false, false, false, false)))
                .containsExactlyInAnyOrder(NotificationType.CHAT_MESSAGE, NotificationType.SECURITY_ALERT);
        assertThat(enabledTypes(preference(false, false, true, false, false, false)))
                .containsExactlyInAnyOrder(
                        NotificationType.TOUR_APPROVED,
                        NotificationType.TOUR_REJECTED,
                        NotificationType.TOUR_CHANGE_APPROVED,
                        NotificationType.TOUR_CHANGE_REJECTED,
                        NotificationType.TOUR_PURCHASED,
                        NotificationType.RESERVATION_CONFIRMED,
                        NotificationType.RESERVATION_CANCELLED,
                        NotificationType.TOUR_CANCELLED,
                        NotificationType.TOUR_COMPLETED,
                        NotificationType.SECURITY_ALERT
                );
        assertThat(enabledTypes(preference(false, false, false, true, false, false)))
                .containsExactlyInAnyOrder(NotificationType.REVIEW_REQUEST, NotificationType.SECURITY_ALERT);
        assertThat(enabledTypes(preference(false, false, false, false, true, false)))
                .containsExactlyInAnyOrder(
                        NotificationType.PAYMENT_SUCCEEDED,
                        NotificationType.PAYMENT_FAILED,
                        NotificationType.REFUND_REQUESTED,
                        NotificationType.REFUND_COMPLETED,
                        NotificationType.REFUND_FAILED,
                        NotificationType.REFUND_MANUAL_REVIEW,
                        NotificationType.EARNING_AVAILABLE,
                        NotificationType.WITHDRAWAL_COMPLETED,
                        NotificationType.SECURITY_ALERT
                );
        assertThat(enabledTypes(preference(false, false, false, false, false, true)))
                .containsExactlyInAnyOrder(
                        NotificationType.RATING_RECEIVED,
                        NotificationType.COMMENT_RECEIVED,
                        NotificationType.SECURITY_ALERT
                );
    }

    @Test
    void enablesAllPushCategoriesWhenUserHasNoSavedPreferences() {
        when(preferenceRepository.findById(USER_ID)).thenReturn(Optional.empty());

        assertThat(Arrays.stream(NotificationType.values())
                .filter(type -> preferenceService.isPushEnabled(USER_ID, type)))
                .containsExactlyInAnyOrder(NotificationType.values());
    }

    private EnumSet<NotificationType> enabledTypes(NotificationPreference preference) {
        when(preferenceRepository.findById(USER_ID)).thenReturn(Optional.of(preference));
        EnumSet<NotificationType> enabled = EnumSet.noneOf(NotificationType.class);
        Arrays.stream(NotificationType.values())
                .filter(type -> preferenceService.isPushEnabled(USER_ID, type))
                .forEach(enabled::add);
        return enabled;
    }

    private NotificationPreference preference(
            boolean upcomingTourReminders,
            boolean chatMessages,
            boolean reservationUpdates,
            boolean reviewRequests,
            boolean paymentsAndEarnings,
            boolean newReviews
    ) {
        NotificationPreference preference = new NotificationPreference(user);
        preference.update(
                upcomingTourReminders,
                chatMessages,
                reservationUpdates,
                reviewRequests,
                paymentsAndEarnings,
                newReviews
        );
        return preference;
    }
}
