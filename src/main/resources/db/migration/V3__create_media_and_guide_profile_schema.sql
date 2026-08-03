CREATE TABLE media_assets (
    id UUID PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES users(id),
    purpose VARCHAR(32) NOT NULL,
    storage_key VARCHAR(255) NOT NULL UNIQUE,
    original_file_name VARCHAR(255) NOT NULL,
    content_type VARCHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_media_purpose
        CHECK (purpose IN ('GUIDE_AVATAR', 'TOUR_COVER')),
    CONSTRAINT chk_media_content_type
        CHECK (content_type IN ('image/jpeg', 'image/png', 'image/webp')),
    CONSTRAINT chk_media_size
        CHECK (size_bytes > 0 AND size_bytes <= 5242880),
    CONSTRAINT chk_media_status
        CHECK (status IN ('PENDING', 'READY', 'DELETED'))
);

CREATE INDEX idx_media_owner ON media_assets(owner_user_id);
CREATE INDEX idx_media_status_created ON media_assets(status, created_at);

CREATE TABLE guide_profiles (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    specialty_title VARCHAR(60) NOT NULL,
    biography TEXT NOT NULL,
    avatar_media_id UUID UNIQUE REFERENCES media_assets(id) ON DELETE SET NULL,
    created_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP(6) WITH TIME ZONE NOT NULL,
    CONSTRAINT chk_guide_specialty_title
        CHECK (CHAR_LENGTH(TRIM(specialty_title)) BETWEEN 2 AND 60),
    CONSTRAINT chk_guide_biography
        CHECK (CHAR_LENGTH(TRIM(biography)) BETWEEN 20 AND 1000)
);

CREATE INDEX idx_guide_profile_avatar ON guide_profiles(avatar_media_id);

CREATE TABLE guide_languages (
    guide_id BIGINT NOT NULL REFERENCES guide_profiles(user_id) ON DELETE CASCADE,
    language_code VARCHAR(3) NOT NULL,
    PRIMARY KEY (guide_id, language_code),
    CONSTRAINT chk_guide_language_code
        CHECK (CHAR_LENGTH(language_code) BETWEEN 2 AND 3)
);
