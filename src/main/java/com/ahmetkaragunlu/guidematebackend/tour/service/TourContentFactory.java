package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.validation.LanguageCodePolicy;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.TourContentRequest;
import com.ahmetkaragunlu.guidematebackend.tour.validation.TourInputPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class TourContentFactory {

    private final LanguageCodePolicy languageCodePolicy;
    private final TourInputPolicy tourInputPolicy;

    public TourChangeSnapshot fromRequest(TourContentRequest request) {
        Set<String> languageCodes = languageCodePolicy.normalize(request.languageCodes());
        return new TourChangeSnapshot(
                request.title(),
                request.description(),
                tourInputPolicy.normalizeCountryCode(request.countryCode()),
                request.cityPlaceId(),
                request.cityName(),
                tourInputPolicy.validateTimeZoneId(request.timeZoneId()),
                tourInputPolicy.normalizeCategoryCode(request.categoryCode()),
                languageCodes.stream().sorted().toList(),
                request.coverMediaId()
        );
    }

    public TourChangeSnapshot validate(TourChangeSnapshot snapshot) {
        Set<String> languageCodes = languageCodePolicy.normalize(snapshot.languageCodes());
        return new TourChangeSnapshot(
                snapshot.title().trim(),
                snapshot.description().trim(),
                tourInputPolicy.normalizeCountryCode(snapshot.countryCode()),
                snapshot.cityPlaceId().trim(),
                snapshot.cityName().trim(),
                tourInputPolicy.validateTimeZoneId(snapshot.timeZoneId()),
                tourInputPolicy.normalizeCategoryCode(snapshot.categoryCode()),
                languageCodes.stream().sorted().toList(),
                snapshot.coverMediaId()
        );
    }
}
