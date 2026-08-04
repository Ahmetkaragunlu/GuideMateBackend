package com.ahmetkaragunlu.guidematebackend.reservation.service;

import com.ahmetkaragunlu.guidematebackend.media.service.MediaReferencePolicy;
import com.ahmetkaragunlu.guidematebackend.reservation.repository.ReservationRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class ReservationMediaReferencePolicy implements MediaReferencePolicy {

    private final ReservationRepository reservationRepository;

    @Override
    public boolean isReferenced(UUID mediaAssetId) {
        return reservationRepository.existsSnapshotMediaReference(mediaAssetId);
    }

    @Override
    public boolean isPubliclyAccessible(UUID mediaAssetId) {
        return false;
    }

    @Override
    public boolean isAccessibleTo(UUID mediaAssetId, Long requesterUserId) {
        return requesterUserId != null
                && reservationRepository.existsSnapshotMediaReferenceForTourist(
                        mediaAssetId,
                        requesterUserId
                );
    }
}
