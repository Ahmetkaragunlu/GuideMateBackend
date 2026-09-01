package com.ahmetkaragunlu.guidematebackend.reservation.mapper;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.dto.ReservationSnapshotResponse;
import com.ahmetkaragunlu.guidematebackend.reservation.service.PurchaseSnapshotCodec;
import com.ahmetkaragunlu.guidematebackend.review.dto.ReviewResponse;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.PublicGuideSummaryResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ReservationMapper {

    private final PurchaseSnapshotCodec snapshotCodec;
    private final MediaUrlFactory mediaUrlFactory;

    public ReservationResponse toResponse(
            Reservation reservation,
            ReviewResponse review,
            ReviewAggregate reviewAggregate,
            int bookedCount
    ) {
        PurchaseSnapshot snapshot = snapshotCodec.decode(reservation.getPurchaseSnapshot());
        MediaReferenceResponse avatar = snapshot.guideAvatarMediaId() == null
                ? null
                : new MediaReferenceResponse(
                        snapshot.guideAvatarMediaId(),
                        mediaUrlFactory.contentUrl(snapshot.guideAvatarMediaId())
                );
        return new ReservationResponse(
                reservation.getId(),
                reservation.getSession().getId(),
                reservation.getVersion(),
                reservation.getParticipantCount(),
                reservation.getUnitPriceMinor(),
                reservation.getTotalPriceMinor(),
                reservation.getCurrencyCode(),
                reservation.getStatus(),
                reservation.getHoldExpiresAt(),
                reservation.getCancellationActor(),
                reservation.getCancellationReason(),
                reservation.getCancelledAt(),
                reservation.getCancellationRefundEligibility(),
                reservation.getCancellationPolicyCode(),
                reservation.getCancellationPolicyVersion(),
                reviewAggregate.averageRating(),
                reviewAggregate.reviewCount(),
                bookedCount,
                reservation.getSession().getCapacity(),
                new ReservationSnapshotResponse(
                        snapshot.tourId(),
                        new PublicGuideSummaryResponse(
                                snapshot.guideId(),
                                snapshot.guideDisplayName(),
                                avatar
                        ),
                        snapshot.title(),
                        snapshot.description(),
                        snapshot.countryCode(),
                        snapshot.cityPlaceId(),
                        snapshot.cityName(),
                        snapshot.timeZoneId(),
                        snapshot.categoryCode(),
                        snapshot.languageCodes(),
                        new MediaReferenceResponse(
                                snapshot.coverMediaId(),
                                mediaUrlFactory.contentUrl(snapshot.coverMediaId())
                        ),
                        snapshot.startsAt(),
                        snapshot.durationMinutes(),
                        snapshot.meetingPoint(),
                        snapshot.unitPriceMinor()
                ),
                review
        );
    }
}
