package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;

import java.util.List;

public record TourProposalResponse(
        String title,
        String description,
        String countryCode,
        String cityPlaceId,
        String cityName,
        String timeZoneId,
        String categoryCode,
        List<String> languageCodes,
        MediaReferenceResponse cover
) {
}
