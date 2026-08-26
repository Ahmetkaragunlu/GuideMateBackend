package com.ahmetkaragunlu.guidematebackend.tour.repository;

import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import com.ahmetkaragunlu.guidematebackend.review.domain.ReviewRankingPolicy;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Fetch;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class TourDiscoveryRepository {

    private final EntityManager entityManager;

    public Page<TourSession> search(TourSearchCriteria criteria) {
        CriteriaBuilder builder = entityManager.getCriteriaBuilder();
        CriteriaQuery<TourSession> query = builder.createQuery(TourSession.class);
        Root<TourSession> session = query.from(TourSession.class);
        Fetch<TourSession, Tour> tourFetch = session.fetch("tour", JoinType.INNER);
        tourFetch.fetch("guide", JoinType.INNER);
        tourFetch.fetch("coverMedia", JoinType.INNER);
        Join<TourSession, Tour> tour = session.join("tour", JoinType.INNER);
        query.select(session);
        query.where(predicates(criteria, builder, query, session, tour).toArray(Predicate[]::new));
        applySort(criteria, builder, query, session, tour);

        TypedQuery<TourSession> typedQuery = entityManager.createQuery(query);
        typedQuery.setFirstResult(criteria.page() * criteria.size());
        typedQuery.setMaxResults(criteria.size());

        long total = count(criteria, builder);
        return new PageImpl<>(
                typedQuery.getResultList(),
                PageRequest.of(criteria.page(), criteria.size()),
                total
        );
    }

    private long count(TourSearchCriteria criteria, CriteriaBuilder builder) {
        CriteriaQuery<Long> countQuery = builder.createQuery(Long.class);
        Root<TourSession> session = countQuery.from(TourSession.class);
        Join<TourSession, Tour> tour = session.join("tour", JoinType.INNER);
        countQuery.select(builder.count(session));
        countQuery.where(predicates(criteria, builder, countQuery, session, tour).toArray(Predicate[]::new));
        return entityManager.createQuery(countQuery).getSingleResult();
    }

    private List<Predicate> predicates(
            TourSearchCriteria criteria,
            CriteriaBuilder builder,
            CriteriaQuery<?> query,
            Root<TourSession> session,
            Join<TourSession, Tour> tour
    ) {
        List<Predicate> predicates = new ArrayList<>();
        predicates.add(builder.equal(tour.get("approvalStatus"), TourApprovalStatus.APPROVED));
        predicates.add(builder.equal(tour.get("guide").get("accountStatus"), AccountStatus.ACTIVE));
        predicates.add(builder.equal(
                tour.get("guide").get("role").get("name"),
                RoleType.ROLE_GUIDE.name()
        ));
        predicates.add(builder.equal(session.get("status"), TourSessionStatus.OPEN_FOR_BOOKING));
        predicates.add(builder.greaterThan(session.get("startsAt"), criteria.now()));
        predicates.add(builder.gt(
                session.get("capacity").as(Long.class),
                occupancy(query, builder, session, criteria)
        ));

        if (criteria.query() != null) {
            String like = "%" + criteria.query().toLowerCase() + "%";
            predicates.add(builder.or(
                    builder.like(builder.lower(tour.get("title")), like),
                    builder.like(builder.lower(tour.get("cityName")), like)
            ));
        }
        if (criteria.guideId() != null) {
            predicates.add(builder.equal(tour.get("guide").get("id"), criteria.guideId()));
        }
        if (criteria.countryCode() != null) {
            predicates.add(builder.equal(tour.get("countryCode"), criteria.countryCode()));
        }
        if (criteria.cityPlaceId() != null) {
            predicates.add(builder.equal(tour.get("cityPlaceId"), criteria.cityPlaceId()));
        }
        if (criteria.categoryCode() != null) {
            predicates.add(builder.equal(tour.get("categoryCode"), criteria.categoryCode()));
        }
        if (!criteria.languageCodes().isEmpty()) {
            Subquery<Integer> languageMatch = query.subquery(Integer.class);
            Root<Tour> languageTour = languageMatch.from(Tour.class);
            Join<Tour, String> language = languageTour.join("languageCodes", JoinType.INNER);
            languageMatch.select(builder.literal(1));
            languageMatch.where(
                    builder.equal(languageTour, tour),
                    language.in(criteria.languageCodes())
            );
            predicates.add(builder.exists(languageMatch));
        }
        if (criteria.minPriceMinor() != null) {
            predicates.add(builder.ge(session.get("priceMinor"), criteria.minPriceMinor()));
        }
        if (criteria.maxPriceMinor() != null) {
            predicates.add(builder.le(session.get("priceMinor"), criteria.maxPriceMinor()));
        }
        if (criteria.minRating() != null) {
            predicates.add(builder.ge(
                    averageRating(query, builder, tour),
                    criteria.minRating()
            ));
        }
        return predicates;
    }

    private void applySort(
            TourSearchCriteria criteria,
            CriteriaBuilder builder,
            CriteriaQuery<TourSession> query,
            Root<TourSession> session,
            Join<TourSession, Tour> tour
    ) {
        switch (criteria.sort()) {
            case PRICE_ASC -> query.orderBy(
                    builder.asc(session.get("priceMinor")),
                    builder.asc(session.get("startsAt")),
                    builder.asc(session.get("id"))
            );
            case PRICE_DESC -> query.orderBy(
                    builder.desc(session.get("priceMinor")),
                    builder.asc(session.get("startsAt")),
                    builder.asc(session.get("id"))
            );
            case RATING_DESC -> {
                Expression<Double> averageRating = averageRating(query, builder, tour);
                Expression<Long> reviewCount = reviewCount(query, builder, tour);
                Expression<Double> reviewCountAsDouble = reviewCount.as(Double.class);
                Expression<Number> weightedRating = builder.quot(
                        builder.sum(
                                builder.prod(averageRating, reviewCountAsDouble),
                                ReviewRankingPolicy.PRIOR_RATING * ReviewRankingPolicy.PRIOR_WEIGHT
                        ),
                        builder.sum(reviewCountAsDouble, ReviewRankingPolicy.PRIOR_WEIGHT)
                );
                query.orderBy(
                        builder.desc(weightedRating),
                        builder.desc(reviewCount),
                        builder.desc(confirmedParticipants(query, builder, tour)),
                        builder.asc(session.get("startsAt")),
                        builder.asc(session.get("id"))
                );
            }
            case STARTS_AT_ASC -> query.orderBy(
                    builder.asc(session.get("startsAt")),
                    builder.asc(session.get("id"))
            );
        }
    }

    private Expression<Long> occupancy(
            CriteriaQuery<?> query,
            CriteriaBuilder builder,
            Root<TourSession> session,
            TourSearchCriteria criteria
    ) {
        Subquery<Long> subquery = query.subquery(Long.class);
        Root<Reservation> reservation = subquery.from(Reservation.class);
        subquery.select(builder.coalesce(
                builder.sumAsLong(reservation.get("participantCount")),
                0L
        ));
        subquery.where(
                builder.equal(reservation.get("session"), session),
                builder.or(
                        reservation.get("status").in(
                                ReservationStatus.CONFIRMED,
                                ReservationStatus.COMPLETED
                        ),
                        builder.and(
                                builder.equal(
                                        reservation.get("status"),
                                        ReservationStatus.PENDING_PAYMENT
                                ),
                                builder.greaterThan(reservation.get("holdExpiresAt"), criteria.now())
                        )
                )
        );
        return subquery;
    }

    private Expression<Double> averageRating(
            CriteriaQuery<?> query,
            CriteriaBuilder builder,
            Join<TourSession, Tour> tour
    ) {
        Subquery<Double> subquery = query.subquery(Double.class);
        Root<Review> review = subquery.from(Review.class);
        subquery.select(builder.coalesce(builder.avg(review.get("rating")), 0.0));
        subquery.where(builder.equal(
                review.get("reservation").get("session").get("tour"),
                tour
        ));
        return subquery;
    }

    private Expression<Long> reviewCount(
            CriteriaQuery<?> query,
            CriteriaBuilder builder,
            Join<TourSession, Tour> tour
    ) {
        Subquery<Long> subquery = query.subquery(Long.class);
        Root<Review> review = subquery.from(Review.class);
        subquery.select(builder.count(review));
        subquery.where(builder.equal(
                review.get("reservation").get("session").get("tour"),
                tour
        ));
        return subquery;
    }

    private Expression<Long> confirmedParticipants(
            CriteriaQuery<?> query,
            CriteriaBuilder builder,
            Join<TourSession, Tour> tour
    ) {
        Subquery<Long> subquery = query.subquery(Long.class);
        Root<Reservation> reservation = subquery.from(Reservation.class);
        subquery.select(builder.coalesce(
                builder.sumAsLong(reservation.get("participantCount")),
                0L
        ));
        subquery.where(
                builder.equal(reservation.get("session").get("tour"), tour),
                reservation.get("status").in(
                        ReservationStatus.CONFIRMED,
                        ReservationStatus.COMPLETED
                )
        );
        return subquery;
    }
}
