package com.ahmetkaragunlu.guidematebackend.tour.service;

import com.ahmetkaragunlu.guidematebackend.common.validation.LanguageCodePolicy;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationCapacityService;
import com.ahmetkaragunlu.guidematebackend.review.service.ReviewQueryService;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSearchSort;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.TourSearchRequest;
import com.ahmetkaragunlu.guidematebackend.tour.mapper.TourMapper;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourDiscoveryRepository;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSearchCriteria;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.tour.validation.TourInputPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TourDiscoveryServiceTest {

    @Mock
    private TourDiscoveryRepository tourDiscoveryRepository;
    @Mock
    private TourSessionRepository tourSessionRepository;
    @Mock
    private GuideProfileRepository guideProfileRepository;
    @Mock
    private LanguageCodePolicy languageCodePolicy;
    @Mock
    private TourInputPolicy tourInputPolicy;
    @Mock
    private TourMapper tourMapper;
    @Mock
    private ReservationCapacityService capacityService;
    @Mock
    private ReviewQueryService reviewQueryService;

    private TourDiscoveryService service;

    @BeforeEach
    void setUp() {
        service = new TourDiscoveryService(
                tourDiscoveryRepository,
                tourSessionRepository,
                guideProfileRepository,
                languageCodePolicy,
                tourInputPolicy,
                tourMapper,
                capacityService,
                reviewQueryService,
                Clock.fixed(Instant.parse("2026-09-23T10:00:00Z"), ZoneOffset.UTC)
        );
        when(languageCodePolicy.normalizeOptional(any())).thenReturn(Set.of());
        when(tourDiscoveryRepository.search(any())).thenReturn(Page.empty());
    }

    @Test
    void preservesMixedCaseCityPlaceIdAfterTrimming() {
        service.search(request(null, "  ChIJiX9L-t9OyhQRv3uPRv5UZ4o  "));

        TourSearchCriteria criteria = capturedCriteria();

        assertThat(criteria.cityPlaceId()).isEqualTo("ChIJiX9L-t9OyhQRv3uPRv5UZ4o");
    }

    @Test
    void keepsFreeTextSearchCaseInsensitive() {
        service.search(request("  ISTANBUL  ", null));

        TourSearchCriteria criteria = capturedCriteria();

        assertThat(criteria.query()).isEqualTo("istanbul");
    }

    private TourSearchCriteria capturedCriteria() {
        ArgumentCaptor<TourSearchCriteria> captor = ArgumentCaptor.forClass(TourSearchCriteria.class);
        verify(tourDiscoveryRepository).search(captor.capture());
        return captor.getValue();
    }

    private TourSearchRequest request(String query, String cityPlaceId) {
        return new TourSearchRequest(
                query,
                null,
                cityPlaceId,
                null,
                null,
                null,
                null,
                null,
                0,
                20,
                TourSearchSort.STARTS_AT_ASC
        );
    }
}
