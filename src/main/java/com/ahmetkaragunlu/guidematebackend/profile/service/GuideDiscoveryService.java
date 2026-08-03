package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;
import com.ahmetkaragunlu.guidematebackend.media.service.MediaUrlFactory;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideSearchItemResponse;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideLevel;
import com.ahmetkaragunlu.guidematebackend.tour.repository.GuideCompletedSessionCount;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class GuideDiscoveryService {

    private final GuideProfileRepository guideProfileRepository;
    private final TourSessionRepository tourSessionRepository;
    private final MediaUrlFactory mediaUrlFactory;
    private final GuideLevelPolicy guideLevelPolicy;

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
        Map<Long, Long> completedCounts = completedCounts(profiles.getContent());
        return PageResponse.from(profiles.map(profile -> toResponse(
                profile,
                completedCounts.getOrDefault(profile.getUserId(), 0L)
        )));
    }

    @Transactional(readOnly = true)
    public List<GuideSearchItemResponse> top(int limit) {
        List<GuideProfile> profiles = guideProfileRepository.findAllPublicProfiles(
                AccountStatus.ACTIVE,
                RoleType.ROLE_GUIDE.name()
        );
        Map<Long, Long> completedCounts = completedCounts(profiles);
        return profiles.stream()
                .map(profile -> toResponse(profile, completedCounts.getOrDefault(profile.getUserId(), 0L)))
                .sorted(Comparator
                        .comparingLong(GuideSearchItemResponse::completedSessionCount).reversed()
                        .thenComparing(GuideSearchItemResponse::displayName)
                        .thenComparing(GuideSearchItemResponse::guideId))
                .limit(limit)
                .toList();
    }

    private Map<Long, Long> completedCounts(List<GuideProfile> profiles) {
        Set<Long> guideIds = profiles.stream().map(GuideProfile::getUserId).collect(Collectors.toSet());
        if (guideIds.isEmpty()) {
            return Map.of();
        }
        return tourSessionRepository.countCompletedSessionsByGuideIds(
                        guideIds,
                        TourSessionStatus.COMPLETED
                ).stream()
                .collect(Collectors.toMap(
                        GuideCompletedSessionCount::getGuideId,
                        GuideCompletedSessionCount::getCompletedSessionCount
                ));
    }

    private GuideSearchItemResponse toResponse(GuideProfile profile, long completedSessionCount) {
        double averageRating = 0.0;
        long reviewCount = 0;
        GuideLevel level = guideLevelPolicy.resolve(completedSessionCount, averageRating, reviewCount);
        MediaReferenceResponse avatar = profile.getAvatar() == null
                ? null
                : new MediaReferenceResponse(
                        profile.getAvatar().getId(),
                        mediaUrlFactory.contentUrl(profile.getAvatar().getId())
                );
        return new GuideSearchItemResponse(
                profile.getUserId(),
                (profile.getUser().getFirstName() + " " + profile.getUser().getLastName()).trim(),
                profile.getSpecialtyTitle(),
                avatar,
                profile.getLanguageCodes().stream().sorted().toList(),
                completedSessionCount,
                0,
                averageRating,
                reviewCount,
                level
        );
    }

    private String trimToNull(String query) {
        if (query == null || query.isBlank()) {
            return null;
        }
        return query.trim().toLowerCase(Locale.ROOT);
    }
}
