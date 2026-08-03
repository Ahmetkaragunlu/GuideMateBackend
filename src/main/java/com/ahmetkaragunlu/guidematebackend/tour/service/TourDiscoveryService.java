package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.LanguageCodePolicy;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.TourSearchSort;
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
    private final Clock clock;

    @Transactional(readOnly = true)
    public PageResponse<TourSearchItemResponse> search(
            String query,
            String countryCode,
            String cityPlaceId,
            String categoryCode,
            List<String> languageCodes,
            Double minRating,
            Long minPriceMinor,
            Long maxPriceMinor,
            int page,
            int size,
            TourSearchSort sort
    ) {
        validateSearchRange(minRating, minPriceMinor, maxPriceMinor);
        Set<String> normalizedLanguages = languageCodePolicy.normalizeOptional(languageCodes);
        TourSearchCriteria criteria = new TourSearchCriteria(
                trimToNull(query),
                countryCode == null ? null : tourInputPolicy.normalizeCountryCode(countryCode),
                trimToNull(cityPlaceId),
                categoryCode == null ? null : tourInputPolicy.normalizeCategoryCode(categoryCode),
                normalizedLanguages,
                minRating,
                minPriceMinor,
                maxPriceMinor,
                page,
                size,
                sort,
                clock.instant()
        );

        if (minRating != null && minRating > 0.0) {
            return new PageResponse<>(List.of(), page, size, 0, 0, true, true);
        }

        Page<TourSession> sessions = tourDiscoveryRepository.search(criteria);
        Map<Long, GuideProfile> profiles = profilesByGuideId(sessions.getContent());
        Page<TourSearchItemResponse> responsePage = sessions.map(session -> tourMapper.toSearchItem(
                session,
                profiles.get(session.getTour().getGuide().getId())
        ));
        return PageResponse.from(responsePage);
    }

    @Transactional(readOnly = true)
    public PageResponse<TourSearchItemResponse> popular(int page, int size) {
        return search(
                null,
                null,
                null,
                null,
                List.of(),
                null,
                null,
                null,
                page,
                size,
                TourSearchSort.RATING_DESC
        );
    }

    @Transactional(readOnly = true)
    public TourDetailResponse getTour(UUID tourId) {
        List<TourSession> sessions = tourSessionRepository.findFuturePublicSessions(
                tourId,
                TourApprovalStatus.APPROVED,
                TourSessionStatus.CANCELLED,
                clock.instant(),
                PageRequest.of(0, 1)
        );
        TourSession session = sessions.stream().findFirst()
                .orElseThrow(() -> new BusinessException(ErrorCode.TOUR_NOT_FOUND));
        GuideProfile profile = requirePublicGuideProfile(session.getTour());
        return tourMapper.toDetail(session.getTour(), List.of(session), profile);
    }

    @Transactional(readOnly = true)
    public TourDetailResponse getSession(UUID sessionId) {
        TourSession session = tourSessionRepository.findPublicSession(
                        sessionId,
                        TourApprovalStatus.APPROVED
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.SESSION_NOT_FOUND));
        GuideProfile profile = requirePublicGuideProfile(session.getTour());
        return tourMapper.toDetail(session.getTour(), List.of(session), profile);
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
                && profile.getUser().getRole() != null
                && RoleType.ROLE_GUIDE.name().equals(profile.getUser().getRole().getName());
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
