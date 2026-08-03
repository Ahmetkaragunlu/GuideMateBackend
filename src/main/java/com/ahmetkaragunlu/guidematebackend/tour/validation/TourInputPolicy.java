package com.ahmetkaragunlu.guidematebackend.tour.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.stereotype.Component;

import java.time.DateTimeException;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class TourInputPolicy {

    private static final Set<String> CATEGORY_CODES = Set.of(
            "culture", "food", "nature", "art", "entertainment", "adventure"
    );
    private static final Set<String> COUNTRY_CODES = Arrays.stream(Locale.getISOCountries())
            .collect(Collectors.toUnmodifiableSet());

    public String normalizeCategoryCode(String categoryCode) {
        String normalized = categoryCode.trim().toLowerCase(Locale.ROOT);
        if (!CATEGORY_CODES.contains(normalized)) {
            throw new BusinessException(ErrorCode.INVALID_CATEGORY_CODE);
        }
        return normalized;
    }

    public String normalizeCountryCode(String countryCode) {
        String normalized = countryCode.trim().toUpperCase(Locale.ROOT);
        if (!COUNTRY_CODES.contains(normalized)) {
            throw new BusinessException(ErrorCode.INVALID_COUNTRY_CODE);
        }
        return normalized;
    }

    public String validateTimeZoneId(String timeZoneId) {
        String normalized = timeZoneId.trim();
        try {
            ZoneId.of(normalized);
        } catch (DateTimeException exception) {
            throw new BusinessException(ErrorCode.INVALID_TIME_ZONE, exception);
        }
        if (!ZoneId.getAvailableZoneIds().contains(normalized)) {
            throw new BusinessException(ErrorCode.INVALID_TIME_ZONE);
        }
        return normalized;
    }
}
