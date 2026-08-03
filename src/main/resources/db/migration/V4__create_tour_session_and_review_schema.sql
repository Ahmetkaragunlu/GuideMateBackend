CREATE TABLE tours (
    id UUID PRIMARY KEY,
    guide_id BIGINT NOT NULL REFERENCES users(id),
    title VARCHAR(120) NOT NULL,
    description TEXT NOT NULL,
    country_code VARCHAR(2) NOT NULL,
    city_place_id VARCHAR(255) NOT NULL,
    city_name VARCHAR(120) NOT NULL,
    time_zone_id VARCHAR(64) NOT NULL,
    category_code VARCHAR(32) NOT NULL,
    cover_media_id UUID NOT NULL REFERENCES media_assets(id),
    approval_status VARCHAR(32) NOT NULL,
    submitted_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    published_at TIMESTAMP(6) WITH TIME ZONE,
    reviewed_at TIMESTAMP(6) WITH TIME ZONE,
    reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    rejection_reason VARCHAR(1000),
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_tour_title
        CHECK (CHAR_LENGTH(TRIM(title)) BETWEEN 3 AND 120),
    CONSTRAINT chk_tour_description
        CHECK (CHAR_LENGTH(TRIM(description)) BETWEEN 20 AND 3000),
    CONSTRAINT chk_tour_country_code
        CHECK (CHAR_LENGTH(country_code) = 2),
    CONSTRAINT chk_tour_category
        CHECK (category_code IN ('culture', 'food', 'nature', 'art', 'entertainment', 'adventure')),
    CONSTRAINT chk_tour_approval_status
        CHECK (approval_status IN ('PENDING_REVIEW', 'APPROVED', 'REJECTED', 'ARCHIVED'))
);

CREATE INDEX idx_tour_guide_status ON tours(guide_id, approval_status);
CREATE INDEX idx_tour_cover ON tours(cover_media_id);
CREATE INDEX idx_tour_public_location ON tours(approval_status, country_code, city_place_id, category_code);

CREATE TABLE tour_languages (
    tour_id UUID NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    language_code VARCHAR(3) NOT NULL,
    PRIMARY KEY (tour_id, language_code),
    CONSTRAINT chk_tour_language_code
        CHECK (CHAR_LENGTH(language_code) BETWEEN 2 AND 3)
);

CREATE TABLE tour_sessions (
    id UUID PRIMARY KEY,
    tour_id UUID NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    meeting_point VARCHAR(500) NOT NULL,
    starts_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    duration_minutes INTEGER NOT NULL,
    price_minor BIGINT NOT NULL,
    currency_code VARCHAR(3) NOT NULL,
    capacity INTEGER NOT NULL,
    status VARCHAR(32) NOT NULL,
    cancellation_actor VARCHAR(16),
    cancellation_reason VARCHAR(1000),
    cancelled_at TIMESTAMP(6) WITH TIME ZONE,
    version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_tour_session_duration CHECK (duration_minutes > 0),
    CONSTRAINT chk_tour_session_price CHECK (price_minor > 0),
    CONSTRAINT chk_tour_session_currency CHECK (currency_code = 'USD'),
    CONSTRAINT chk_tour_session_capacity CHECK (capacity > 0),
    CONSTRAINT chk_tour_session_status
        CHECK (status IN ('OPEN_FOR_BOOKING', 'CLOSED', 'COMPLETED', 'CANCELLED')),
    CONSTRAINT chk_tour_session_cancellation_actor
        CHECK (cancellation_actor IS NULL OR cancellation_actor IN ('GUIDE', 'ADMIN')),
    CONSTRAINT chk_tour_session_cancellation_fields
        CHECK (
            (status = 'CANCELLED' AND cancellation_actor IS NOT NULL
                AND cancellation_reason IS NOT NULL AND cancelled_at IS NOT NULL)
            OR
            (status <> 'CANCELLED' AND cancellation_actor IS NULL
                AND cancellation_reason IS NULL AND cancelled_at IS NULL)
        )
);

CREATE INDEX idx_tour_session_tour ON tour_sessions(tour_id);
CREATE INDEX idx_tour_session_status_start ON tour_sessions(status, starts_at);

CREATE TABLE tour_change_requests (
    id UUID PRIMARY KEY,
    tour_id UUID NOT NULL REFERENCES tours(id) ON DELETE CASCADE,
    base_version BIGINT NOT NULL,
    proposed_snapshot JSONB NOT NULL,
    proposed_cover_media_id UUID NOT NULL REFERENCES media_assets(id),
    status VARCHAR(16) NOT NULL,
    pending_guard BOOLEAN,
    submitted_by BIGINT NOT NULL REFERENCES users(id),
    reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    submitted_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    reviewed_at TIMESTAMP(6) WITH TIME ZONE,
    rejection_reason VARCHAR(1000),
    CONSTRAINT chk_tour_change_status
        CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'CANCELLED')),
    CONSTRAINT chk_tour_change_pending_guard
        CHECK (
            (status = 'PENDING' AND pending_guard = TRUE)
            OR (status <> 'PENDING' AND pending_guard IS NULL)
        ),
    CONSTRAINT uq_tour_change_pending UNIQUE (tour_id, pending_guard)
);

CREATE INDEX idx_tour_change_tour_status ON tour_change_requests(tour_id, status);
CREATE INDEX idx_tour_change_submitted ON tour_change_requests(status, submitted_at);
CREATE INDEX idx_tour_change_cover ON tour_change_requests(proposed_cover_media_id);
