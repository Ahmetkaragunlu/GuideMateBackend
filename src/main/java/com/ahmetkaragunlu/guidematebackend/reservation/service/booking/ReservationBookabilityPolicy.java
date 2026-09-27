package com.ahmetkaragunlu.guidematebackend.reservation.service.booking;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.tour.domain.tour.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class ReservationBookabilityPolicy {

    public void requireBookable(TourSession session, Instant now) {
        if (!isBookable(session, now)) {
            throw new BusinessException(ErrorCode.SESSION_NOT_BOOKABLE);
        }
    }

    public boolean isBookable(TourSession session, Instant now) {
        User guide = session.getTour().getGuide();
        return session.getTour().getApprovalStatus() == TourApprovalStatus.APPROVED
                && session.getStatus() == TourSessionStatus.OPEN_FOR_BOOKING
                && session.getStartsAt().isAfter(now)
                && guide.getAccountStatus() == AccountStatus.ACTIVE
                && guide.hasRole(RoleType.ROLE_GUIDE);
    }
}
