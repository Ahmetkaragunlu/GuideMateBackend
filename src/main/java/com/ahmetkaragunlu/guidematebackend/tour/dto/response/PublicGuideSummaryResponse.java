package com.ahmetkaragunlu.guidematebackend.tour.dto.response;

import com.ahmetkaragunlu.guidematebackend.media.dto.MediaReferenceResponse;

public record PublicGuideSummaryResponse(
        Long guideId,
        String displayName,
        MediaReferenceResponse avatar
) {
}
