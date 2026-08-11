package com.ahmetkaragunlu.guidematebackend.notification.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Objects;

@Getter
@Entity
@Table(name = "notification_preferences")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class NotificationPreference {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @MapsId
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "upcoming_tour_reminders_enabled", nullable = false)
    private boolean upcomingTourRemindersEnabled = true;

    @Column(name = "chat_messages_enabled", nullable = false)
    private boolean chatMessagesEnabled = true;

    @Column(name = "reservation_updates_enabled", nullable = false)
    private boolean reservationUpdatesEnabled = true;

    @Column(name = "review_requests_enabled", nullable = false)
    private boolean reviewRequestsEnabled = true;

    @Column(name = "payments_and_earnings_enabled", nullable = false)
    private boolean paymentsAndEarningsEnabled = true;

    @Column(name = "new_reviews_enabled", nullable = false)
    private boolean newReviewsEnabled = true;

    public NotificationPreference(User user) {
        this.user = Objects.requireNonNull(user);
    }

    public void update(
            Boolean upcomingTourRemindersEnabled,
            Boolean chatMessagesEnabled,
            Boolean reservationUpdatesEnabled,
            Boolean reviewRequestsEnabled,
            Boolean paymentsAndEarningsEnabled,
            Boolean newReviewsEnabled
    ) {
        if (upcomingTourRemindersEnabled != null) {
            this.upcomingTourRemindersEnabled = upcomingTourRemindersEnabled;
        }
        if (chatMessagesEnabled != null) {
            this.chatMessagesEnabled = chatMessagesEnabled;
        }
        if (reservationUpdatesEnabled != null) {
            this.reservationUpdatesEnabled = reservationUpdatesEnabled;
        }
        if (reviewRequestsEnabled != null) {
            this.reviewRequestsEnabled = reviewRequestsEnabled;
        }
        if (paymentsAndEarningsEnabled != null) {
            this.paymentsAndEarningsEnabled = paymentsAndEarningsEnabled;
        }
        if (newReviewsEnabled != null) {
            this.newReviewsEnabled = newReviewsEnabled;
        }
    }
}
