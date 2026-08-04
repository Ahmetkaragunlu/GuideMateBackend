package com.ahmetkaragunlu.guidematebackend.review.repository;

import com.ahmetkaragunlu.guidematebackend.review.domain.Review;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ReviewRepository extends JpaRepository<Review, UUID> {

    Optional<Review> findByReservation_Id(UUID reservationId);

    boolean existsByReservation_Id(UUID reservationId);

    @EntityGraph(attributePaths = {"reservation"})
    List<Review> findAllByReservation_IdIn(Collection<UUID> reservationIds);

    @EntityGraph(attributePaths = {"reservation", "reservation.tourist"})
    @Query(
            value = """
                    SELECT review FROM Review review
                    WHERE review.reservation.session.tour.id = :tourId
                    ORDER BY review.createdAt DESC, review.id DESC
                    """,
            countQuery = """
                    SELECT COUNT(review) FROM Review review
                    WHERE review.reservation.session.tour.id = :tourId
                    """
    )
    Page<Review> findPublicByTourId(@Param("tourId") UUID tourId, Pageable pageable);

    @Query("""
            SELECT review.reservation.session.tour.id AS tourId,
                   AVG(review.rating) AS averageRating,
                   COUNT(review) AS reviewCount
            FROM Review review
            WHERE review.reservation.session.tour.id IN :tourIds
            GROUP BY review.reservation.session.tour.id
            """)
    List<TourRatingSummary> summarizeByTourIds(@Param("tourIds") Collection<UUID> tourIds);

    @Query("""
            SELECT review.reservation.session.tour.guide.id AS guideId,
                   AVG(review.rating) AS averageRating,
                   COUNT(review) AS reviewCount
            FROM Review review
            WHERE review.reservation.session.tour.guide.id IN :guideIds
            GROUP BY review.reservation.session.tour.guide.id
            """)
    List<GuideRatingSummary> summarizeByGuideIds(@Param("guideIds") Collection<Long> guideIds);
}
