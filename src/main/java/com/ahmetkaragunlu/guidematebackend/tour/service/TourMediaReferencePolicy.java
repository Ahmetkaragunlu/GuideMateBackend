package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.media.service.MediaReferencePolicy;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeRequestStatus;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourChangeRequestRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TourMediaReferencePolicy implements MediaReferencePolicy {

    private final TourRepository tourRepository;
    private final TourChangeRequestRepository changeRequestRepository;

    @Override
    public boolean isReferenced(UUID mediaAssetId) {
        return tourRepository.existsByCoverMedia_Id(mediaAssetId)
                || changeRequestRepository.existsByProposedCoverMedia_IdAndStatus(
                        mediaAssetId,
                        TourChangeRequestStatus.PENDING
                );
    }

    @Override
    public boolean isPubliclyAccessible(UUID mediaAssetId) {
        return tourRepository.existsPublicCoverReference(
                mediaAssetId,
                TourApprovalStatus.APPROVED,
                AccountStatus.ACTIVE,
                RoleType.ROLE_GUIDE.name()
        );
    }
}
