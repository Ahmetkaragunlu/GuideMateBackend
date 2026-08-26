package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuidePerformanceSummary;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideSearchItemResponse;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideRankingRepository;
import com.ahmetkaragunlu.guidematebackend.review.domain.ReviewRankingPolicy;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class GuideDiscoveryService {

    private final GuideProfileRepository guideProfileRepository;
    private final GuideRankingRepository guideRankingRepository;
    private final GuidePerformanceService guidePerformanceService;
    private final MediaUrlFactory mediaUrlFactory;

    @Transactional(readOnly = true)
    public PageResponse<GuideSearchItemResponse> search(String query, int page, int size) {
        PageRequest pageable = PageRequest.of(
                page,
                size,
                Sort.by("user.lastName").ascending().and(Sort.by("user.firstName").ascending())
        );
        String normalizedQuery = trimToNull(query);
        Page<GuideProfile> profiles = normalizedQuery == null
                ? guideProfileRepository.findPublicProfiles(
                        AccountStatus.ACTIVE,
                        RoleType.ROLE_GUIDE.name(),
                        pageable
                )
                : guideProfileRepository.searchPublicProfiles(
                        normalizedQuery,
                        AccountStatus.ACTIVE,
                        RoleType.ROLE_GUIDE.name(),
                        pageable
                );
        Map<Long, GuidePerformanceSummary> performance = performance(profiles.getContent());
        return PageResponse.from(profiles.map(profile -> toResponse(
                profile,
                performance.get(profile.getUserId())
        )));
    }

    @Transactional(readOnly = true)
    public List<GuideSearchItemResponse> top(int limit) {
        List<Long> rankedGuideIds = guideRankingRepository.findTopGuideIds(
                AccountStatus.ACTIVE.name(),
                RoleType.ROLE_GUIDE.name(),
                ReviewRankingPolicy.PRIOR_RATING,
                ReviewRankingPolicy.PRIOR_WEIGHT,
                limit
        );
        Map<Long, GuideProfile> profiles = guideProfileRepository.findAllByUserIdIn(rankedGuideIds).stream()
                .collect(Collectors.toMap(
                        GuideProfile::getUserId,
                        profile -> profile,
                        (first, ignored) -> first,
                        LinkedHashMap::new
                ));
        Map<Long, GuidePerformanceSummary> performance = performance(profiles);
        return rankedGuideIds.stream()
                .map(profiles::get)
                .filter(java.util.Objects::nonNull)
                .map(profile -> toResponse(profile, performance.get(profile.getUserId())))
                .toList();
    }

    private Map<Long, GuidePerformanceSummary> performance(List<GuideProfile> profiles) {
        Set<Long> guideIds = profiles.stream().map(GuideProfile::getUserId).collect(Collectors.toSet());
        return guidePerformanceService.getAll(guideIds);
    }

    private Map<Long, GuidePerformanceSummary> performance(Map<Long, GuideProfile> profiles) {
        return guidePerformanceService.getAll(profiles.keySet());
    }

    private GuideSearchItemResponse toResponse(
            GuideProfile profile,
            GuidePerformanceSummary performance
    ) {
        MediaReferenceResponse avatar = profile.getAvatar() == null
                ? null
                : new MediaReferenceResponse(
                        profile.getAvatar().getId(),
                        mediaUrlFactory.contentUrl(profile.getAvatar().getId())
                );
        return new GuideSearchItemResponse(
                profile.getUserId(),
                profile.getUser().displayName(),
                profile.getSpecialtyTitle(),
                avatar,
                profile.getLanguageCodes().stream().sorted().toList(),
                performance.completedSessionCount(),
                performance.totalParticipantCount(),
                performance.averageRating(),
                performance.reviewCount(),
                performance.level()
        );
    }

    private String trimToNull(String query) {
        if (query == null || query.isBlank()) {
            return null;
        }
        return query.trim().toLowerCase(Locale.ROOT);
    }
}
