package com.ahmetkaragunlu.guidematebackend.tour.dto.response.tour;

import com.ahmetkaragunlu.guidematebackend.media.dto.response.MediaReferenceResponse;

public record PublicGuideSummaryResponse(
        Long guideId,
        String displayName,
        MediaReferenceResponse avatar
) {
}
