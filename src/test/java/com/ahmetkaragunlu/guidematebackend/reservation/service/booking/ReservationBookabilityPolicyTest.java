package com.ahmetkaragunlu.guidematebackend.reservation.service.booking;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.tour.domain.tour.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.tour.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ReservationBookabilityPolicyTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    private final ReservationBookabilityPolicy policy = new ReservationBookabilityPolicy();

    @Test
    void acceptsApprovedFutureSessionOwnedByActiveGuide() {
        TourSession session = session(TourSessionStatus.OPEN_FOR_BOOKING, NOW.plusSeconds(3_600));

        assertThat(policy.isBookable(session, NOW)).isTrue();
    }

    @Test
    void rejectsSessionThatHasAlreadyStarted() {
        TourSession session = session(TourSessionStatus.OPEN_FOR_BOOKING, NOW);

        assertThatThrownBy(() -> policy.requireBookable(session, NOW))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.SESSION_NOT_BOOKABLE));
    }

    private TourSession session(TourSessionStatus status, Instant startsAt) {
        TourSession session = mock(TourSession.class);
        Tour tour = mock(Tour.class);
        User guide = mock(User.class);
        when(session.getTour()).thenReturn(tour);
        when(session.getStatus()).thenReturn(status);
        when(session.getStartsAt()).thenReturn(startsAt);
        when(tour.getApprovalStatus()).thenReturn(TourApprovalStatus.APPROVED);
        when(tour.getGuide()).thenReturn(guide);
        when(guide.getAccountStatus()).thenReturn(AccountStatus.ACTIVE);
        when(guide.hasRole(RoleType.ROLE_GUIDE)).thenReturn(true);
        return session;
    }
}
