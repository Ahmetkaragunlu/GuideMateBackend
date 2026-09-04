ALTER TABLE tour_sessions
    DROP CONSTRAINT chk_tour_session_status;

ALTER TABLE tour_sessions
    ADD CONSTRAINT chk_tour_session_status
        CHECK (status IN ('OPEN_FOR_BOOKING', 'CLOSED', 'COMPLETED', 'CANCELLED', 'EXPIRED'));
