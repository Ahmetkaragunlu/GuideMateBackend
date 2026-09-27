package com.ahmetkaragunlu.guidematebackend.tour.dto.request.query;

import com.ahmetkaragunlu.guidematebackend.tour.search.TourSearchSort;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class TourSearchRequestTest {

    private static final ValidatorFactory VALIDATOR_FACTORY = Validation.buildDefaultValidatorFactory();
    private static final Validator VALIDATOR = VALIDATOR_FACTORY.getValidator();

    @AfterAll
    static void closeValidatorFactory() {
        VALIDATOR_FACTORY.close();
    }

    @Test
    void appliesStablePagingAndSortDefaults() {
        TourSearchRequest request = request(null, null, null, null);

        assertThat(request.page()).isZero();
        assertThat(request.size()).isEqualTo(20);
        assertThat(request.sort()).isEqualTo(TourSearchSort.STARTS_AT_ASC);
    }

    @Test
    void preservesExplicitPagingAndSort() {
        TourSearchRequest request = request(2, 40, TourSearchSort.PRICE_DESC, 4.5);

        assertThat(request.page()).isEqualTo(2);
        assertThat(request.size()).isEqualTo(40);
        assertThat(request.sort()).isEqualTo(TourSearchSort.PRICE_DESC);
        assertThat(request.minRating()).isEqualTo(4.5);
    }

    @Test
    void rejectsOutOfRangePagingRatingAndNegativePrice() {
        TourSearchRequest request = new TourSearchRequest(
                "query",
                "TR",
                "istanbul",
                "culture",
                List.of("en"),
                5.1,
                -1L,
                10_000L,
                -1,
                51,
                TourSearchSort.STARTS_AT_ASC
        );

        assertThat(VALIDATOR.validate(request))
                .extracting(violation -> violation.getPropertyPath().toString())
                .containsExactlyInAnyOrder("minRating", "minPriceMinor", "page", "size");
    }

    @Test
    void acceptsValidSearchContract() {
        assertThat(VALIDATOR.validate(request(0, 50, TourSearchSort.RATING_DESC, 0.0)))
                .isEmpty();
    }

    private TourSearchRequest request(
            Integer page,
            Integer size,
            TourSearchSort sort,
            Double minRating
    ) {
        return new TourSearchRequest(
                "museum",
                "TR",
                "istanbul",
                "culture",
                List.of("en", "tr"),
                minRating,
                0L,
                10_000L,
                page,
                size,
                sort
        );
    }
}
