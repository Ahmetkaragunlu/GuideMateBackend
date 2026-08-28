ALTER TABLE media_assets
    DROP CONSTRAINT chk_media_purpose;

UPDATE media_assets
SET purpose = 'USER_AVATAR'
WHERE purpose = 'GUIDE_AVATAR';

ALTER TABLE media_assets
    ADD CONSTRAINT chk_media_purpose
        CHECK (purpose IN ('USER_AVATAR', 'TOUR_COVER'));

ALTER TABLE users
    ADD COLUMN avatar_media_id UUID UNIQUE REFERENCES media_assets(id) ON DELETE SET NULL;

UPDATE users user_account
SET avatar_media_id = guide_profile.avatar_media_id
FROM guide_profiles guide_profile
WHERE guide_profile.user_id = user_account.id
  AND guide_profile.avatar_media_id IS NOT NULL;

DROP INDEX IF EXISTS idx_guide_profile_avatar;

ALTER TABLE guide_profiles
    DROP COLUMN avatar_media_id;
