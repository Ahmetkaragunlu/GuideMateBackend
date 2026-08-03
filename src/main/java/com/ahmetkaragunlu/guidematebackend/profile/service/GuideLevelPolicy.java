package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.tour.dto.response.GuideLevel;
import org.springframework.stereotype.Component;

@Component
public class GuideLevelPolicy {

    public GuideLevel resolve(long completedSessionCount, double averageRating, long reviewCount) {
        if (completedSessionCount >= 100 && averageRating >= 4.8 && reviewCount >= 30) {
            return GuideLevel.LEGENDARY;
        }
        if (completedSessionCount >= 20 && averageRating >= 4.5 && reviewCount >= 10) {
            return GuideLevel.SUPER;
        }
        if (completedSessionCount >= 5 && averageRating >= 3.7 && reviewCount >= 3) {
            return GuideLevel.SILVER;
        }
        return GuideLevel.APPROVED;
    }
}
