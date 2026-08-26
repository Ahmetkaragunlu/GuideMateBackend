package com.ahmetkaragunlu.guidematebackend.tour.repository;

import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;

import java.util.UUID;

public interface AdminTourReviewRepository extends Repository<Tour, UUID> {

    @Query(
            value = """
                    SELECT
                        pending.review_id AS "reviewId",
                        pending.review_type AS "reviewType",
                        pending.tour_id AS "tourId",
                        pending.guide_id AS "guideId",
                        pending.guide_display_name AS "guideDisplayName",
                        pending.title AS "title",
                        pending.submitted_at AS "submittedAt"
                    FROM (
                        SELECT
                            tour.id AS review_id,
                            'NEW_TOUR' AS review_type,
                            tour.id AS tour_id,
                            tour.guide_id AS guide_id,
                            TRIM(CONCAT(guide.first_name, ' ', guide.last_name)) AS guide_display_name,
                            tour.title AS title,
                            tour.submitted_at AS submitted_at
                        FROM tours tour
                        JOIN users guide ON guide.id = tour.guide_id
                        WHERE tour.approval_status = 'PENDING_REVIEW'

                        UNION ALL

                        SELECT
                            request.id AS review_id,
                            'TOUR_CHANGE' AS review_type,
                            tour.id AS tour_id,
                            tour.guide_id AS guide_id,
                            TRIM(CONCAT(guide.first_name, ' ', guide.last_name)) AS guide_display_name,
                            request.proposed_snapshot ->> 'title' AS title,
                            request.submitted_at AS submitted_at
                        FROM tour_change_requests request
                        JOIN tours tour ON tour.id = request.tour_id
                        JOIN users guide ON guide.id = tour.guide_id
                        WHERE request.status = 'PENDING'
                    ) pending
                    ORDER BY pending.submitted_at DESC, pending.review_id
                    """,
            countQuery = """
                    SELECT COUNT(*)
                    FROM (
                        SELECT tour.id
                        FROM tours tour
                        WHERE tour.approval_status = 'PENDING_REVIEW'

                        UNION ALL

                        SELECT request.id
                        FROM tour_change_requests request
                        WHERE request.status = 'PENDING'
                    ) pending
                    """,
            nativeQuery = true
    )
    Page<AdminTourReviewSummaryProjection> findPendingReviews(Pageable pageable);
}
