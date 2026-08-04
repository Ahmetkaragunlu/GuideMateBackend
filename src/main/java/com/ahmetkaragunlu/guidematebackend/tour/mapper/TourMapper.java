package com.ahmetkaragunlu.guidematebackend.tour.mapper;

import com.ahmetkaragunlu.guidematebackend.media.domain.MediaAsset;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideTourCardResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.PublicGuideSummaryResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourProposalResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourSearchItemResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourSessionResponse;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TourMapper {

    private final MediaUrlFactory mediaUrlFactory;

    public TourDetailResponse toDetail(
            Tour tour,
            List<TourSession> sessions,
            GuideProfile guideProfile,
            Map<UUID, Integer> occupiedCounts,
            ReviewAggregate reviews
    ) {
        return new TourDetailResponse(
                tour.getId(),
                tour.getVersion(),
                toGuideSummary(tour.getGuide(), guideProfile),
                tour.getTitle(),
                tour.getDescription(),
                tour.getCountryCode(),
                tour.getCityPlaceId(),
                tour.getCityName(),
                tour.getTimeZoneId(),
                tour.getCategoryCode(),
                sortedLanguages(tour),
                toMediaReference(tour.getCoverMedia()),
                tour.getApprovalStatus(),
                tour.getSubmittedAt(),
                tour.getPublishedAt(),
                tour.getReviewedAt(),
                tour.getRejectionReason(),
                reviews.averageRating(),
                reviews.reviewCount(),
                sessions.stream()
                        .map(session -> toSession(
                                session,
                                occupiedCounts.getOrDefault(session.getId(), 0)
                        ))
                        .toList()
        );
    }

    public TourSessionResponse toSession(TourSession session, int bookedCount) {
        return new TourSessionResponse(
                session.getId(),
                session.getTour().getId(),
                session.getVersion(),
                session.getMeetingPoint(),
                session.getStartsAt(),
                session.getDurationMinutes(),
                session.getPriceMinor(),
                session.getCurrencyCode(),
                session.getCapacity(),
                bookedCount,
                session.getCapacity() - bookedCount,
                session.getStatus(),
                session.getCancellationActor(),
                session.getCancellationReason(),
                session.getCancelledAt()
        );
    }

    public GuideTourCardResponse toGuideCard(TourSession session, int bookedCount) {
        Tour tour = session.getTour();
        return new GuideTourCardResponse(
                tour.getId(),
                session.getId(),
                tour.getVersion(),
                session.getVersion(),
                tour.getTitle(),
                tour.getCityName(),
                tour.getCountryCode(),
                tour.getTimeZoneId(),
                tour.getCategoryCode(),
                sortedLanguages(tour),
                toMediaReference(tour.getCoverMedia()),
                session.getStartsAt(),
                session.getDurationMinutes(),
                session.getPriceMinor(),
                session.getCurrencyCode(),
                bookedCount,
                Math.max(0, session.getCapacity() - bookedCount),
                tour.getApprovalStatus(),
                session.getStatus(),
                tour.getRejectionReason(),
                tour.getApprovalStatus() == TourApprovalStatus.REJECTED && tour.getPublishedAt() == null
        );
    }

    public TourSearchItemResponse toSearchItem(
            TourSession session,
            GuideProfile guideProfile,
            int bookedCount,
            ReviewAggregate reviews
    ) {
        Tour tour = session.getTour();
        return new TourSearchItemResponse(
                tour.getId(),
                session.getId(),
                tour.getTitle(),
                tour.getCategoryCode(),
                tour.getCityName(),
                tour.getCountryCode(),
                tour.getCityPlaceId(),
                session.getStartsAt(),
                tour.getTimeZoneId(),
                session.getDurationMinutes(),
                session.getPriceMinor(),
                session.getCurrencyCode(),
                Math.max(0, session.getCapacity() - bookedCount),
                sortedLanguages(tour),
                toMediaReference(tour.getCoverMedia()),
                reviews.averageRating(),
                reviews.reviewCount(),
                toGuideSummary(tour.getGuide(), guideProfile)
        );
    }

    public TourProposalResponse toProposal(TourChangeSnapshot snapshot, MediaAsset coverMedia) {
        return new TourProposalResponse(
                snapshot.title(),
                snapshot.description(),
                snapshot.countryCode(),
                snapshot.cityPlaceId(),
                snapshot.cityName(),
                snapshot.timeZoneId(),
                snapshot.categoryCode(),
                snapshot.languageCodes(),
                toMediaReference(coverMedia)
        );
    }

    public MediaReferenceResponse toMediaReference(MediaAsset media) {
        return new MediaReferenceResponse(media.getId(), mediaUrlFactory.contentUrl(media.getId()));
    }

    private PublicGuideSummaryResponse toGuideSummary(User guide, GuideProfile profile) {
        MediaReferenceResponse avatar = profile == null || profile.getAvatar() == null
                ? null
                : toMediaReference(profile.getAvatar());
        return new PublicGuideSummaryResponse(
                guide.getId(),
                (guide.getFirstName() + " " + guide.getLastName()).trim(),
                avatar
        );
    }

    private List<String> sortedLanguages(Tour tour) {
        return tour.getLanguageCodes().stream().sorted(Comparator.naturalOrder()).toList();
    }
}
