package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.LanguageCodePolicy;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewAggregate;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSearchSort;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.TourSearchRequest;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourDetailResponse;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.TourSearchItemResponse;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourDiscoveryRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSearchCriteria;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.tour.validation.TourInputPolicy;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class TourDiscoveryService {

    private final TourDiscoveryRepository tourDiscoveryRepository;
    private final TourSessionRepository tourSessionRepository;
    private final GuideProfileRepository guideProfileRepository;
    private final LanguageCodePolicy languageCodePolicy;
    private final TourInputPolicy tourInputPolicy;
    private final TourMapper tourMapper;
    private final ReservationCapacityService capacityService;
    private final ReviewQueryService reviewQueryService;
    private final Clock clock;

    @Transactional(readOnly = true)
    public PageResponse<TourSearchItemResponse> search(TourSearchRequest request) {
        validateSearchRange(request.minRating(), request.minPriceMinor(), request.maxPriceMinor());
        Set<String> normalizedLanguages = languageCodePolicy.normalizeOptional(request.languageCodes());
        TourSearchCriteria criteria = new TourSearchCriteria(
                trimToNull(request.q()),
                null,
                request.countryCode() == null
                        ? null
                        : tourInputPolicy.normalizeCountryCode(request.countryCode()),
                trimToNull(request.cityPlaceId()),
                request.categoryCode() == null
                        ? null
                        : tourInputPolicy.normalizeCategoryCode(request.categoryCode()),
                normalizedLanguages,
                request.minRating(),
                request.minPriceMinor(),
                request.maxPriceMinor(),
                request.page(),
                request.size(),
                request.sort(),
                clock.instant()
        );

        return search(criteria);
    }

    @Transactional(readOnly = true)
    public PageResponse<TourSearchItemResponse> popular(Long guideId, int page, int size) {
        TourSearchCriteria criteria = new TourSearchCriteria(
                null,
                guideId,
                null,
                null,
                null,
                Set.of(),
                null,
                null,
                null,
                page,
                size,
                TourSearchSort.RATING_DESC,
                clock.instant()
        );
        return search(criteria);
    }

    private PageResponse<TourSearchItemResponse> search(TourSearchCriteria criteria) {
        Page<TourSession> sessions = tourDiscoveryRepository.search(criteria);
        Map<Long, GuideProfile> profiles = profilesByGuideId(sessions.getContent());
        Map<UUID, Integer> occupiedCounts = capacityService.occupiedCounts(sessionIds(sessions.getContent()));
        Map<UUID, ReviewAggregate> reviews = reviewQueryService.tourAggregates(tourIds(sessions.getContent()));
        return PageResponse.from(sessions.map(session -> tourMapper.toSearchItem(
                session,
                profiles.get(session.getTour().getGuide().getId()),
                occupiedCounts.getOrDefault(session.getId(), 0),
                reviews.getOrDefault(session.getTour().getId(), ReviewAggregate.EMPTY)
        )));
    }

    @Transactional(readOnly = true)
    public TourDetailResponse getTour(UUID tourId) {
        List<TourSession> sessions = tourSessionRepository.findFuturePublicSessions(
                tourId,
                TourApprovalStatus.APPROVED,
                TourSessionStatus.OPEN_FOR_BOOKING,
                clock.instant(),
                PageRequest.of(0, 50)
        );
        Map<UUID, Integer> occupiedCounts = capacityService.occupiedCounts(sessionIds(sessions));
        TourSession session = sessions.stream()
                .filter(candidate -> capacityService.availableCapacity(
                        candidate,
                        occupiedCounts.getOrDefault(candidate.getId(), 0)
                ) > 0)
                .findFirst()
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
        GuideProfile profile = requirePublicGuideProfile(session.getTour());
        ReviewAggregate reviews = reviewQueryService.tourAggregates(List.of(tourId))
                .getOrDefault(tourId, ReviewAggregate.EMPTY);
        return tourMapper.toDetail(
                session.getTour(),
                List.of(session),
                profile,
                occupiedCounts,
                reviews
        );
    }

    @Transactional(readOnly = true)
    public TourDetailResponse getSession(UUID sessionId) {
        TourSession session = tourSessionRepository.findPublicSession(
                        sessionId,
                        TourApprovalStatus.APPROVED
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.SESSION_NOT_FOUND));
        GuideProfile profile = requirePublicGuideProfile(session.getTour());
        int occupiedCount = capacityService.occupiedCount(sessionId);
        ReviewAggregate reviews = reviewQueryService.tourAggregates(
                        List.of(session.getTour().getId())
                )
                .getOrDefault(session.getTour().getId(), ReviewAggregate.EMPTY);
        return tourMapper.toDetail(
                session.getTour(),
                List.of(session),
                profile,
                Map.of(sessionId, occupiedCount),
                reviews
        );
    }

    private List<UUID> sessionIds(List<TourSession> sessions) {
        return sessions.stream().map(TourSession::getId).toList();
    }

    private Set<UUID> tourIds(List<TourSession> sessions) {
        return sessions.stream().map(session -> session.getTour().getId()).collect(Collectors.toSet());
    }

    private Map<Long, GuideProfile> profilesByGuideId(List<TourSession> sessions) {
        Set<Long> guideIds = sessions.stream()
                .map(session -> session.getTour().getGuide().getId())
                .collect(Collectors.toSet());
        if (guideIds.isEmpty()) {
            return Map.of();
        }
        return guideProfileRepository.findAllByUserIdIn(guideIds).stream()
                .collect(Collectors.toMap(GuideProfile::getUserId, Function.identity()));
    }

    private GuideProfile requirePublicGuideProfile(Tour tour) {
        GuideProfile profile = guideProfileRepository.findByUserId(tour.getGuide().getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
        boolean publicGuide = profile.getUser().getAccountStatus() == AccountStatus.ACTIVE
                && profile.getUser().hasRole(RoleType.ROLE_GUIDE);
        if (!publicGuide) {
            throw new BusinessException(ErrorCode.TOUR_NOT_FOUND);
        }
        return profile;
    }

    private void validateSearchRange(Double minRating, Long minPriceMinor, Long maxPriceMinor) {
        if (minRating != null && (minRating < 0.0 || minRating > 5.0)) {
            throw new BusinessException(ErrorCode.VALIDATION_FAILED);
        }
        if (minPriceMinor != null && minPriceMinor < 0
                || maxPriceMinor != null && maxPriceMinor < 0
                || minPriceMinor != null && maxPriceMinor != null && minPriceMinor > maxPriceMinor) {
            throw new BusinessException(ErrorCode.VALIDATION_FAILED);
        }
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }
}
