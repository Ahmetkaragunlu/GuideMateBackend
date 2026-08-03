package com.ahmetkaragunlu.guidematebackend.tour.repository;

import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourApprovalStatus;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSessionStatus;
import com.ahmetkaragunlu.guidematebackend.tour.dto.request.TourSearchSort;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Fetch;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
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
        query.select(session).distinct(true);
        query.where(predicates(criteria, builder, session, tour).toArray(Predicate[]::new));
        applySort(criteria.sort(), builder, query, session);

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
        countQuery.select(builder.countDistinct(session));
        countQuery.where(predicates(criteria, builder, session, tour).toArray(Predicate[]::new));
        return entityManager.createQuery(countQuery).getSingleResult();
    }

    private List<Predicate> predicates(
            TourSearchCriteria criteria,
            CriteriaBuilder builder,
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

        if (criteria.query() != null) {
            String like = "%" + criteria.query().toLowerCase() + "%";
            predicates.add(builder.or(
                    builder.like(builder.lower(tour.get("title")), like),
                    builder.like(builder.lower(tour.get("cityName")), like)
            ));
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
            Join<Tour, String> languages = tour.join("languageCodes", JoinType.INNER);
            predicates.add(languages.in(criteria.languageCodes()));
        }
        if (criteria.minPriceMinor() != null) {
            predicates.add(builder.ge(session.get("priceMinor"), criteria.minPriceMinor()));
        }
        if (criteria.maxPriceMinor() != null) {
            predicates.add(builder.le(session.get("priceMinor"), criteria.maxPriceMinor()));
        }
        return predicates;
    }

    private void applySort(
            TourSearchSort sort,
            CriteriaBuilder builder,
            CriteriaQuery<TourSession> query,
            Root<TourSession> session
    ) {
        switch (sort) {
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
            case RATING_DESC, STARTS_AT_ASC -> query.orderBy(
                    builder.asc(session.get("startsAt")),
                    builder.asc(session.get("id"))
            );
        }
    }
}
