package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class PurchaseSnapshotFactory {

    public static final int CURRENT_SNAPSHOT_VERSION = 1;

    private final GuideProfileRepository guideProfileRepository;
    private final CancellationPolicy cancellationPolicy;

    public PurchaseSnapshot create(TourSession session, int participantCount, long totalPriceMinor) {
        Tour tour = session.getTour();
        GuideProfile guideProfile = guideProfileRepository.findByUserId(tour.getGuide().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.GUIDE_PROFILE_NOT_FOUND));
        var avatarMediaId = tour.getGuide().getAvatarMediaId();
        return new PurchaseSnapshot(
                CURRENT_SNAPSHOT_VERSION,
                tour.getId(),
                tour.getTitle(),
                tour.getDescription(),
                tour.getCoverMedia().getId(),
                tour.getGuide().getId(),
                tour.getGuide().displayName(),
                avatarMediaId,
                tour.getCountryCode(),
                tour.getCityPlaceId(),
                tour.getCityName(),
                tour.getTimeZoneId(),
                tour.getCategoryCode(),
                tour.getLanguageCodes().stream().sorted().toList(),
                session.getId(),
                session.getStartsAt(),
                session.getDurationMinutes(),
                session.getMeetingPoint(),
                session.getPriceMinor(),
                totalPriceMinor,
                session.getCurrencyCode(),
                participantCount,
                cancellationPolicy.currentCode(),
                cancellationPolicy.currentVersion()
        );
    }
}
