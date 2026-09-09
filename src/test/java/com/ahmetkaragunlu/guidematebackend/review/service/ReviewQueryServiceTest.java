package com.ahmetkaragunlu.guidematebackend.review.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.review.mapper.ReviewMapper;
import com.ahmetkaragunlu.guidematebackend.review.repository.ReviewRepository;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReviewQueryServiceTest {

    @Mock
    private ReviewRepository reviewRepository;
    @Mock
    private TourRepository tourRepository;
    @Mock
    private ReviewMapper reviewMapper;

    @InjectMocks
    private ReviewQueryService service;

    @Test
    void listsReviewsForAnOwnedTourWithoutRequiringPublicVisibility() {
        UUID tourId = UUID.randomUUID();
        User guide = org.mockito.Mockito.mock(User.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        PageRequest pageRequest = PageRequest.of(0, 20);

        when(guide.getId()).thenReturn(42L);
        when(tour.getId()).thenReturn(tourId);
        when(tourRepository.findOwnedDetails(tourId, 42L)).thenReturn(Optional.of(tour));
        when(reviewRepository.findByTourId(tourId, pageRequest)).thenReturn(Page.empty(pageRequest));

        var result = service.getOwnedTourReviews(guide, tourId, 0, 20);

        assertThat(result.content()).isEmpty();
        verify(reviewRepository).findByTourId(tourId, pageRequest);
    }

    @Test
    void hidesAReviewListWhenTheGuideDoesNotOwnTheTour() {
        UUID tourId = UUID.randomUUID();
        User guide = org.mockito.Mockito.mock(User.class);

        when(guide.getId()).thenReturn(42L);
        when(tourRepository.findOwnedDetails(tourId, 42L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getOwnedTourReviews(guide, tourId, 0, 20))
                .isInstanceOfSatisfying(
                        BusinessException.class,
                        exception -> assertThat(exception.getErrorCode())
                                .isEqualTo(ErrorCode.TOUR_NOT_FOUND)
                );
        verify(reviewRepository, never()).findByTourId(any(), any());
    }
}
