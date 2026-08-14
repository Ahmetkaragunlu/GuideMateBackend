package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourChangeSnapshot;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TourLocationPolicyTest {

    private final TourLocationPolicy locationPolicy = new TourLocationPolicy();

    @Test
    void acceptsUnchangedLocation() {
        Tour tour = tourInIstanbul();
        TourChangeSnapshot proposed = proposedLocation("TR", "istanbul", "Istanbul", "Europe/Istanbul");

        assertThatCode(() -> locationPolicy.requireUnchanged(tour, proposed))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsChangedLocation() {
        Tour tour = tourInIstanbul();
        TourChangeSnapshot proposed = proposedLocation("FR", "paris", "Paris", "Europe/Paris");

        assertThatThrownBy(() -> locationPolicy.requireUnchanged(tour, proposed))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.TOUR_LOCATION_LOCKED)
                );
    }

    private Tour tourInIstanbul() {
        Tour tour = mock(Tour.class);
        when(tour.getCountryCode()).thenReturn("TR");
        when(tour.getCityPlaceId()).thenReturn("istanbul");
        when(tour.getCityName()).thenReturn("Istanbul");
        when(tour.getTimeZoneId()).thenReturn("Europe/Istanbul");
        return tour;
    }

    private TourChangeSnapshot proposedLocation(
            String countryCode,
            String cityPlaceId,
            String cityName,
            String timeZoneId
    ) {
        TourChangeSnapshot proposed = mock(TourChangeSnapshot.class);
        when(proposed.countryCode()).thenReturn(countryCode);
        when(proposed.cityPlaceId()).thenReturn(cityPlaceId);
        when(proposed.cityName()).thenReturn(cityName);
        when(proposed.timeZoneId()).thenReturn(timeZoneId);
        return proposed;
    }
}
