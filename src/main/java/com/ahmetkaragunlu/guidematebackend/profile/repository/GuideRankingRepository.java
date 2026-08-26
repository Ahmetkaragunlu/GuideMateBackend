package com.ahmetkaragunlu.guidematebackend.profile.repository;

import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface GuideRankingRepository extends Repository<GuideProfile, Long> {

    @Query(value = """
            WITH completed_sessions AS (
                SELECT tour.guide_id, COUNT(session.id) AS completed_session_count
                FROM tours tour
                JOIN tour_sessions session ON session.tour_id = tour.id
                WHERE session.status = 'COMPLETED'
                GROUP BY tour.guide_id
            ),
            guide_ratings AS (
                SELECT tour.guide_id,
                       AVG(review.rating) AS average_rating,
                       COUNT(review.id) AS review_count
                FROM reviews review
                JOIN reservations reservation ON reservation.id = review.reservation_id
                JOIN tour_sessions session ON session.id = reservation.session_id
                JOIN tours tour ON tour.id = session.tour_id
                GROUP BY tour.guide_id
            )
            SELECT profile.user_id
            FROM guide_profiles profile
            JOIN users guide ON guide.id = profile.user_id
            JOIN roles role ON role.id = guide.role_id
            LEFT JOIN completed_sessions completed ON completed.guide_id = profile.user_id
            LEFT JOIN guide_ratings ratings ON ratings.guide_id = profile.user_id
            WHERE guide.account_status = :accountStatus
              AND role.name = :roleName
            ORDER BY
                (
                    COALESCE(ratings.average_rating, 0) * COALESCE(ratings.review_count, 0)
                    + :priorRating * :priorWeight
                ) / (COALESCE(ratings.review_count, 0) + :priorWeight) DESC,
                COALESCE(ratings.review_count, 0) DESC,
                COALESCE(completed.completed_session_count, 0) DESC,
                TRIM(CONCAT(guide.first_name, ' ', guide.last_name)) COLLATE "C",
                profile.user_id
            LIMIT :limit
            """, nativeQuery = true)
    List<Long> findTopGuideIds(
            @Param("accountStatus") String accountStatus,
            @Param("roleName") String roleName,
            @Param("priorRating") double priorRating,
            @Param("priorWeight") double priorWeight,
            @Param("limit") int limit
    );
}
