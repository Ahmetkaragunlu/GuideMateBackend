package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import org.springframework.stereotype.Component;

@Component
public class TourLocationPolicy {

    public void requireUnchanged(Tour tour, TourChangeSnapshot proposed) {
        if (!tour.getCountryCode().equals(proposed.countryCode())
                || !tour.getCityPlaceId().equals(proposed.cityPlaceId())
                || !tour.getCityName().equals(proposed.cityName())
                || !tour.getTimeZoneId().equals(proposed.timeZoneId())) {
            throw new BusinessException(ErrorCode.TOUR_LOCATION_LOCKED);
        }
    }
}
