-- This script is executed only by the guarded demo profile inside one transaction.

create temporary table demo_unique_surnames on commit drop as
with surname_parts(prefixes, suffixes) as (
    values (
        array[
            'Ak', 'Al', 'Ar', 'Ay', 'Baş', 'Bay', 'Boz', 'Çetin', 'Demir', 'Er',
            'Gök', 'Gün', 'Işık', 'Kara', 'Kılıç', 'Öz', 'Sarı', 'Şen', 'Tan', 'Yıldız'
        ]::text[],
        array[
            'bay', 'bek', 'ber', 'can', 'çam', 'dağ', 'dal', 'deniz', 'doğan', 'er',
            'gül', 'kaya', 'kurt', 'soy', 'taş'
        ]::text[]
    )
)
select
    number as person_index,
    prefixes[1 + ((number - 1) / 15)] || suffixes[1 + ((number - 1) % 15)] as last_name
from generate_series(1, 300) number
cross join surname_parts;

create unique index demo_unique_surnames_last_name_unique
    on demo_unique_surnames (last_name);

insert into users (
    id, first_name, last_name, email, password, google_subject, role_id,
    role_selected, account_status, token_version, created_at, created_by,
    updated_at, updated_by
)
select
    1000 + number,
    (array[
        'Aylin', 'Deniz', 'Elif', 'Mert', 'Selin', 'Emre', 'Leyla', 'Can',
        'Ece', 'Burak', 'Ceren', 'Kaan', 'Dila', 'Ozan', 'Aslı', 'Eren',
        'İrem', 'Barış', 'Sude', 'Onur', 'Melis', 'Tolga', 'Naz', 'Ulaş'
    ])[1 + ((number - 1) % 24)],
    surname.last_name,
    'tourist' || lpad(number::text, 3, '0') || '@demo.guidemate.test',
    current_setting('guidemate.demo_password_hash'),
    null,
    (select id from roles where name = 'ROLE_TOURIST'),
    true,
    'ACTIVE',
    0,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - interval '18 months' + number * interval '2 hours',
    'demo-seed',
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - interval '30 days' + number * interval '20 minutes',
    'demo-seed'
from generate_series(1, 250) as number
join demo_unique_surnames surname on surname.person_index = number;

insert into users (
    id, first_name, last_name, email, password, google_subject, role_id,
    role_selected, account_status, token_version, created_at, created_by,
    updated_at, updated_by
)
select
    2000 + number,
    (array[
        'Ada', 'Kerem', 'Derya', 'Bora', 'Zeynep', 'Arda', 'Sema', 'Cem',
        'Defne', 'Alp', 'İpek', 'Yiğit', 'Narin', 'Koray', 'Güneş', 'Pınar'
    ])[1 + ((number - 1) % 16)],
    surname.last_name,
    'guide' || lpad(number::text, 3, '0') || '@demo.guidemate.test',
    current_setting('guidemate.demo_password_hash'),
    null,
    (select id from roles where name = 'ROLE_GUIDE'),
    true,
    'ACTIVE',
    0,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - interval '20 months' + number * interval '3 days',
    'demo-seed',
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - interval '14 days' + number * interval '2 hours',
    'demo-seed'
from generate_series(1, 50) as number
join demo_unique_surnames surname on surname.person_index = 250 + number;

insert into users (
    id, first_name, last_name, email, password, google_subject, role_id,
    role_selected, account_status, token_version, created_at, created_by,
    updated_at, updated_by
)
values
    (
        3001, 'GuideMate', 'Yönetici', 'admin@demo.guidemate.test',
        current_setting('guidemate.demo_password_hash'), null,
        (select id from roles where name = 'ROLE_ADMIN'), true, 'ACTIVE', 0,
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '24 months',
        'demo-seed', current_setting('guidemate.demo_reference_instant')::timestamptz, 'demo-seed'
    ),
    (
        3101, 'Pelin', 'Onaylı', 'pending.valid@demo.guidemate.test',
        current_setting('guidemate.demo_password_hash'), null, null, false,
        'PENDING_VERIFICATION', 0,
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '2 hours',
        'demo-seed', null, null
    ),
    (
        3102, 'Volkan', 'Süreli', 'pending.expired@demo.guidemate.test',
        current_setting('guidemate.demo_password_hash'), null, null, false,
        'PENDING_VERIFICATION', 0,
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '14 days',
        'demo-seed', null, null
    ),
    (
        3103, 'Ahu', 'Seçkin', 'role.selection@demo.guidemate.test',
        current_setting('guidemate.demo_password_hash'), null, null, false,
        'ACTIVE', 0,
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '1 day',
        'demo-seed', null, null
    ),
    (
        3104, 'Tarık', 'Durgun', 'disabled.tourist@demo.guidemate.test',
        current_setting('guidemate.demo_password_hash'), null,
        (select id from roles where name = 'ROLE_TOURIST'), true, 'DISABLED', 2,
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '12 months',
        'demo-seed', current_setting('guidemate.demo_reference_instant')::timestamptz - interval '30 days',
        'demo-seed'
    ),
    (
        3105, 'Yasemin', 'Bekler', 'disabled.guide@demo.guidemate.test',
        current_setting('guidemate.demo_password_hash'), null,
        (select id from roles where name = 'ROLE_GUIDE'), true, 'DISABLED', 3,
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '18 months',
        'demo-seed', current_setting('guidemate.demo_reference_instant')::timestamptz - interval '60 days',
        'demo-seed'
    );

select setval(pg_get_serial_sequence('users', 'id'), (select max(id) from users), true);

insert into media_assets (
    id, owner_user_id, purpose, storage_key, original_file_name,
    content_type, size_bytes, status, created_at, updated_at
)
select
    fixture.id,
    fixture.owner_id,
    fixture.purpose,
    fixture.storage_key,
    fixture.original_file_name,
    fixture.content_type,
    fixture.size_bytes,
    'READY',
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '90 days',
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '30 days'
from demo_media_fixture fixture;

update users user_account
set avatar_media_id = media.id,
    updated_at = current_setting('guidemate.demo_reference_instant')::timestamptz - interval '1 day',
    updated_by = 'demo-seed'
from media_assets media
where media.owner_user_id = user_account.id
  and media.purpose = 'USER_AVATAR'
  and user_account.id between 1001 and 2050;

insert into guide_profiles (
    user_id, specialty_title, biography, created_at, updated_at
)
select
    guide.id,
    (array[
        'Yerel Kültür Anlatıcısı', 'Lezzet ve Pazar Uzmanı', 'Doğa Rotası Rehberi',
        'Sanat ve Mimari Rehberi', 'Aile Deneyimi Rehberi', 'Macera Rotası Lideri'
    ])[1 + ((guide.id - 2001) % 6)],
    format(
        'Ben %s %s. Küçük gruplara özenli ve samimi deneyimler sunan lisanslı bir yerel rehberim. '
            || 'Her misafir için uyarlanabilen rotalarda pratik bilgiler ve semt hikâyeleri paylaşıyorum.',
        guide.first_name,
        guide.last_name
    ),
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '16 months'
        + (guide.id - 2001) * interval '3 days',
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '10 days'
        + (guide.id - 2001) * interval '2 hours'
from users guide
where guide.id between 2001 and 2050;

insert into guide_languages (guide_id, language_code)
select
    guide_id,
    case
        when language_position = 0 then 'tr'
        else (array['en', 'fr', 'it', 'es', 'de', 'pt', 'nl', 'el', 'ja', 'ko', 'ar', 'no'])[
            1 + ((guide_id - 2001 + (language_position - 1) * 4) % 12)
        ]
    end
from generate_series(2001, 2050) as guide_id
cross join generate_series(0, 3) as language_position;

insert into wallets (id, user_id, currency_code, version, created_at, updated_at)
select
    pg_temp.demo_uuid('wallet-' || user_id),
    user_id,
    'USD',
    0,
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '15 months'
        + (user_id % 200) * interval '1 day',
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '1 day'
from (
    select generate_series(1001, 1250) as user_id
    union all
    select generate_series(2001, 2050) as user_id
) demo_users;

insert into notification_preferences (
    user_id, upcoming_tour_reminders_enabled, chat_messages_enabled,
    reservation_updates_enabled, review_requests_enabled,
    payments_and_earnings_enabled, new_reviews_enabled
)
select
    user_id,
    user_id % 7 <> 0,
    user_id % 7 <> 1,
    user_id % 7 <> 2,
    user_id % 7 <> 3,
    user_id % 7 <> 4,
    user_id % 7 <> 5
from (
    select generate_series(1001, 1250) as user_id
    union all
    select generate_series(2001, 2050) as user_id
) demo_users;

with destinations(
    destination_index, country_code, city_place_id, city_name, time_zone_id, landmark_name
) as (
    values
        (1, 'TR', 'demo-istanbul-sultanahmet', 'İstanbul', 'Europe/Istanbul', 'Sultanahmet'),
        (2, 'TR', 'demo-istanbul-ayasofya', 'İstanbul', 'Europe/Istanbul', 'Ayasofya'),
        (3, 'TR', 'demo-istanbul-galata', 'İstanbul', 'Europe/Istanbul', 'Galata ve Karaköy'),
        (4, 'TR', 'demo-nevsehir-kapadokya', 'Nevşehir', 'Europe/Istanbul', 'Kapadokya'),
        (5, 'TR', 'demo-izmir-efes', 'İzmir', 'Europe/Istanbul', 'Efes Antik Kenti'),
        (6, 'TR', 'demo-denizli-pamukkale', 'Denizli', 'Europe/Istanbul', 'Pamukkale'),
        (7, 'TR', 'demo-antalya-kaleici', 'Antalya', 'Europe/Istanbul', 'Kaleiçi'),
        (8, 'TR', 'demo-mugla-bodrum', 'Muğla', 'Europe/Istanbul', 'Bodrum Kalesi'),
        (9, 'TR', 'demo-mugla-oludeniz', 'Muğla', 'Europe/Istanbul', 'Ölüdeniz'),
        (10, 'TR', 'demo-canakkale-troya', 'Çanakkale', 'Europe/Istanbul', 'Troya Antik Kenti'),
        (11, 'TR', 'demo-bursa-cumalikizik', 'Bursa', 'Europe/Istanbul', 'Cumalıkızık'),
        (12, 'TR', 'demo-karabuk-safranbolu', 'Karabük', 'Europe/Istanbul', 'Safranbolu'),
        (13, 'TR', 'demo-edirne-selimiye', 'Edirne', 'Europe/Istanbul', 'Selimiye Camii'),
        (14, 'TR', 'demo-konya-mevlana', 'Konya', 'Europe/Istanbul', 'Mevlana Müzesi'),
        (15, 'TR', 'demo-ankara-anitkabir', 'Ankara', 'Europe/Istanbul', 'Anıtkabir'),
        (16, 'TR', 'demo-mardin-eski-kent', 'Mardin', 'Europe/Istanbul', 'Eski Mardin'),
        (17, 'TR', 'demo-sanliurfa-gobeklitepe', 'Şanlıurfa', 'Europe/Istanbul', 'Göbeklitepe'),
        (18, 'TR', 'demo-gaziantep-zeugma', 'Gaziantep', 'Europe/Istanbul', 'Zeugma'),
        (19, 'TR', 'demo-adiyaman-nemrut', 'Adıyaman', 'Europe/Istanbul', 'Nemrut Dağı'),
        (20, 'TR', 'demo-trabzon-sumela', 'Trabzon', 'Europe/Istanbul', 'Sümela Manastırı'),
        (21, 'TR', 'demo-rize-ayder', 'Rize', 'Europe/Istanbul', 'Ayder Yaylası'),
        (22, 'TR', 'demo-kars-ani', 'Kars', 'Europe/Istanbul', 'Ani Harabeleri'),
        (23, 'TR', 'demo-van-akdamar', 'Van', 'Europe/Istanbul', 'Akdamar Adası'),
        (24, 'TR', 'demo-amasya-kral-kaya', 'Amasya', 'Europe/Istanbul', 'Kral Kaya Mezarları')
), tour_plan as (
    select
        number as tour_index,
        2006 + ((number - 1) % 45) as guide_id,
        destination.*,
        (array['culture', 'food', 'nature', 'art', 'entertainment', 'adventure'])[
            1 + ((number - 1) % 6)
        ] as category_code,
        (array['Kültür', 'Lezzet', 'Doğa', 'Sanat', 'Eğlence', 'Macera'])[
            1 + ((number - 1) % 6)
        ] as category_title,
        case
            when number <= 130 then 'APPROVED'
            when number <= 150 then 'PENDING_REVIEW'
            when number <= 165 then 'REJECTED'
            else 'ARCHIVED'
        end as approval_status
    from generate_series(1, 180) number
    join destinations destination on destination.destination_index = 1 + ((number - 1) % 24)
)
insert into tours (
    id, guide_id, title, description, country_code, city_place_id, city_name,
    time_zone_id, category_code, cover_media_id, approval_status, submitted_at,
    published_at, reviewed_at, reviewed_by, rejection_reason, version,
    created_at, updated_at
)
select
    pg_temp.demo_uuid('tour-' || tour_index),
    guide_id,
    format(
        '%s %s Rotası %s',
        landmark_name,
        category_title,
        lpad(tour_index::text, 3, '0')
    ),
    format(
        '%s ve çevresini yerel hikâyeler, tarihî bilgiler ve planlı fotoğraf duraklarıyla '
            || 'keşfedeceğiniz dengeli bir %s rotası. Küçük gruplara uygun programda sorular için de zaman ayrılır.',
        landmark_name,
        lower(category_title)
    ),
    country_code,
    city_place_id,
    city_name,
    time_zone_id,
    category_code,
    pg_temp.demo_uuid('tour-cover-' || tour_index),
    approval_status,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - interval '20 months' + tour_index * interval '3 days',
    case when approval_status in ('APPROVED', 'ARCHIVED') then
        current_setting('guidemate.demo_reference_instant')::timestamptz
            - interval '18 months' + tour_index * interval '3 days'
    end,
    case when approval_status <> 'PENDING_REVIEW' then
        current_setting('guidemate.demo_reference_instant')::timestamptz
            - interval '18 months' + tour_index * interval '3 days'
    end,
    case when approval_status <> 'PENDING_REVIEW' then 3001 end,
    case when approval_status = 'REJECTED' then
        'Rota açıklamasında buluşma ve erişilebilirlik bilgilerinin netleştirilmesi gerekiyor.'
    end,
    0,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - interval '20 months' + tour_index * interval '3 days',
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - interval '10 days' + tour_index * interval '30 minutes'
from tour_plan;

insert into tour_languages (tour_id, language_code)
select
    pg_temp.demo_uuid('tour-' || tour_index),
    case
        when language_position = 0 then 'tr'
        else (array['en', 'fr', 'it', 'es', 'de', 'pt', 'nl', 'el', 'ja', 'ko', 'ar', 'no'])[
            1 + (((2006 + ((tour_index - 1) % 45)) - 2001
                + (language_position - 1) * 4) % 12)
        ]
    end
from generate_series(1, 180) as tour_index
cross join lateral generate_series(0, 1 + ((tour_index - 1) % 3)) as language_position;

create temporary table demo_session_plan on commit drop as
with completed_allocation as (
    select
        guide_id,
        ordinal,
        row_number() over (order by guide_id, ordinal)::integer as session_number
    from generate_series(2006, 2050) guide_id
    cross join lateral generate_series(
        1,
        case
            when guide_id between 2006 and 2020 then 5
            when guide_id between 2021 and 2035 then 4
            when guide_id between 2036 and 2045 then 5
            when guide_id between 2046 and 2049 then 20
            when guide_id = 2050 then 100
        end
    ) ordinal
), completed as (
    select
        session_number,
        guide_id,
        (guide_id - 2006) + 1 + 45 * ((ordinal - 1) % 2) as tour_index,
        'COMPLETED'::varchar as status,
        current_setting('guidemate.demo_reference_instant')::timestamptz
            - (366 - session_number) * interval '1 day' as starts_at,
        90 + (session_number % 7) * 30 as duration_minutes,
        1500 + (session_number % 68) * 500 as price_minor,
        15 + (session_number % 6) as capacity,
        ordinal
    from completed_allocation
), open_sessions as (
    select
        365 + ordinal as session_number,
        2006 + ((ordinal - 1) % 45) as guide_id,
        ((2006 + ((ordinal - 1) % 45)) - 2006) + 1 + 45 * ((ordinal - 1) % 2) as tour_index,
        'OPEN_FOR_BOOKING'::varchar as status,
        current_setting('guidemate.demo_reference_instant')::timestamptz
            + (1 + ((ordinal - 1) % 120)) * interval '1 day'
            + (9 + ordinal % 8) * interval '1 hour' as starts_at,
        60 + (ordinal % 8) * 30 as duration_minutes,
        2000 + (ordinal % 65) * 500 as price_minor,
        case
            when ordinal <= 20 then 3
            when ordinal <= 40 then 4
            when ordinal <= 60 then 10
            when ordinal <= 90 then 5
            when ordinal <= 120 then 12
            else 6
        end as capacity,
        ordinal
    from generate_series(1, 150) ordinal
), closed_sessions as (
    select
        515 + ordinal as session_number,
        2006 + ((ordinal - 1) % 45) as guide_id,
        ((2006 + ((ordinal - 1) % 45)) - 2006) + 1 as tour_index,
        'CLOSED'::varchar as status,
        current_setting('guidemate.demo_reference_instant')::timestamptz
            + (15 + ordinal) * interval '1 day' as starts_at,
        120 + (ordinal % 6) * 30 as duration_minutes,
        3000 + (ordinal % 50) * 500 as price_minor,
        10 as capacity,
        ordinal
    from generate_series(1, 25) ordinal
), cancelled_sessions as (
    select
        540 + ordinal as session_number,
        2006 + ((ordinal - 1) % 45) as guide_id,
        ((2006 + ((ordinal - 1) % 45)) - 2006) + 46 as tour_index,
        'CANCELLED'::varchar as status,
        current_setting('guidemate.demo_reference_instant')::timestamptz
            + (20 + ordinal) * interval '1 day' as starts_at,
        120 + (ordinal % 6) * 30 as duration_minutes,
        2500 + (ordinal % 40) * 500 as price_minor,
        8 as capacity,
        ordinal
    from generate_series(1, 20) ordinal
)
select * from completed
union all select * from open_sessions
union all select * from closed_sessions
union all select * from cancelled_sessions;

insert into tour_sessions (
    id, tour_id, meeting_point, starts_at, duration_minutes, price_minor,
    currency_code, capacity, status, cancellation_actor, cancellation_reason,
    cancelled_at, cancellation_idempotency_key, upcoming_reminder_sent_at,
    version, created_at, updated_at
)
select
    pg_temp.demo_uuid('session-' || session_number),
    pg_temp.demo_uuid('tour-' || tour_index),
    format('Ana ziyaretçi girişi, %s numaralı buluşma tabelası', lpad(session_number::text, 3, '0')),
    starts_at,
    duration_minutes,
    price_minor,
    'USD',
    capacity,
    status,
    case when status = 'CANCELLED' then 'GUIDE' end,
    case when status = 'CANCELLED' then 'Rehber planlanan tarihte uygun olmadığı için tur iptal edildi.' end,
    case when status = 'CANCELLED' then starts_at - interval '7 days' end,
    case when status = 'CANCELLED' then 'demo-session-cancel-' || session_number end,
    case
        when status = 'OPEN_FOR_BOOKING' and session_number % 5 = 0
        then current_setting('guidemate.demo_reference_instant')::timestamptz - interval '1 hour'
    end,
    0,
    least(
        starts_at - interval '60 days',
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '400 days'
            + session_number * interval '12 hours'
    ),
    case
        when status = 'CANCELLED' then starts_at - interval '7 days'
        else current_setting('guidemate.demo_reference_instant')::timestamptz - interval '2 days'
    end
from demo_session_plan;

insert into tour_change_requests (
    id, tour_id, base_version, proposed_snapshot, proposed_cover_media_id,
    status, pending_guard, submitted_by, reviewed_by, submitted_at,
    reviewed_at, rejection_reason
)
select
    pg_temp.demo_uuid('tour-change-' || number),
    tour.id,
    tour.version,
    jsonb_build_object(
        'title', tour.title || ' Güncellenmiş Rota',
        'description', tour.description || ' Önerilen rota daha sakin bir son durak içeriyor.',
        'countryCode', tour.country_code,
        'cityPlaceId', tour.city_place_id,
        'cityName', tour.city_name,
        'timeZoneId', tour.time_zone_id,
        'categoryCode', tour.category_code,
        'languageCodes', (select jsonb_agg(language_code order by language_code)
                          from tour_languages where tour_id = tour.id),
        'coverMediaId', tour.cover_media_id
    ),
    tour.cover_media_id,
    case when number <= 10 then 'PENDING'
         when number <= 20 then 'APPROVED'
         else 'REJECTED' end,
    case when number <= 10 then true end,
    tour.guide_id,
    case when number > 10 then 3001 end,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (40 - number) * interval '2 days',
    case when number > 10 then
        current_setting('guidemate.demo_reference_instant')::timestamptz
            - (39 - number) * interval '2 days'
    end,
    case when number > 20 then 'Önerilen buluşma bilgilerinin netleştirilmesi gerekiyor.' end
from generate_series(1, 30) number
join tours tour on tour.id = pg_temp.demo_uuid('tour-' || number);

create temporary table demo_reservation_plan on commit drop as
with completed as (
    select
        number as reservation_index,
        case
            when number <= 420 then 1231 + ((number - 1) % 20)
            else 1126 + ((number - 421) % 70)
        end as tourist_id,
        1 + (((number - 1) * 37) % 365) as session_number,
        1 + (number % 5) as participant_count,
        'COMPLETED'::varchar as status,
        null::timestamptz as hold_expires_at,
        null::varchar as cancellation_actor,
        null::varchar as cancellation_reason,
        null::timestamptz as cancelled_at,
        null::varchar as refund_eligibility,
        null::boolean as active_guard
    from generate_series(1, 850) number
), confirmed as (
    select
        850 + number as reservation_index,
        1061 + ((number - 1) % 65) as tourist_id,
        case
            when number <= 180 then 365 + ceil(number / 3.0)::integer
            else 425 + ceil((number - 180) / 2.0)::integer
        end as session_number,
        1 as participant_count,
        'CONFIRMED'::varchar as status,
        null::timestamptz as hold_expires_at,
        null::varchar as cancellation_actor,
        null::varchar as cancellation_reason,
        null::timestamptz as cancelled_at,
        null::varchar as refund_eligibility,
        true as active_guard
    from generate_series(1, 300) number
), pending_payment as (
    select
        1150 + number as reservation_index,
        1061 + ((number - 1) % 65) as tourist_id,
        495 + number as session_number,
        1 as participant_count,
        'PENDING_PAYMENT'::varchar as status,
        current_setting('guidemate.demo_reference_instant')::timestamptz + interval '30 days' as hold_expires_at,
        null::varchar as cancellation_actor,
        null::varchar as cancellation_reason,
        null::timestamptz as cancelled_at,
        null::varchar as refund_eligibility,
        true as active_guard
    from generate_series(1, 20) number
), expired as (
    select
        1170 + number as reservation_index,
        1196 + ((number - 1) % 35) as tourist_id,
        1 + (((number - 1) * 11) % 365) as session_number,
        1 + (number % 3) as participant_count,
        'EXPIRED'::varchar as status,
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '60 days' as hold_expires_at,
        null::varchar as cancellation_actor,
        null::varchar as cancellation_reason,
        null::timestamptz as cancelled_at,
        null::varchar as refund_eligibility,
        null::boolean as active_guard
    from generate_series(1, 40) number
), cancelled as (
    select
        1210 + number as reservation_index,
        1196 + ((number - 1) % 35) as tourist_id,
        case
            when number <= 65 then 365 + 1 + ((number - 1) % 120)
            else 540 + 1 + ((number - 66) % 20)
        end as session_number,
        1 + (number % 3) as participant_count,
        'CANCELLED'::varchar as status,
        null::timestamptz as hold_expires_at,
        case when number <= 65 then 'TOURIST' else 'GUIDE' end as cancellation_actor,
        case when number <= 65
            then 'Bu rezervasyon için seyahat planı değişti.'
            else 'Rehber planlanan tur oturumunu iptal etti.'
        end as cancellation_reason,
        current_setting('guidemate.demo_reference_instant')::timestamptz
            - (90 - number) * interval '6 hours' as cancelled_at,
        case
            when number <= 35 then 'FULL_REFUND'
            when number <= 55 then 'NO_REFUND'
            when number <= 65 then 'NOT_APPLICABLE'
            else 'FULL_REFUND'
        end as refund_eligibility,
        null::boolean as active_guard
    from generate_series(1, 90) number
)
select * from completed
union all select * from confirmed
union all select * from pending_payment
union all select * from expired
union all select * from cancelled;

insert into reservations (
    id, session_id, tourist_id, participant_count, unit_price_minor,
    total_price_minor, currency_code, status, hold_expires_at,
    cancellation_actor, cancellation_reason, cancelled_at,
    cancellation_refund_eligibility, cancellation_policy_code,
    cancellation_policy_version, snapshot_version, purchase_snapshot,
    idempotency_key, cancellation_idempotency_key, active_guard,
    upcoming_reminder_sent_at, version, created_at, updated_at
)
select
    pg_temp.demo_uuid('reservation-' || plan.reservation_index),
    session.id,
    plan.tourist_id,
    plan.participant_count,
    session.price_minor,
    session.price_minor * plan.participant_count,
    'USD',
    plan.status,
    plan.hold_expires_at,
    plan.cancellation_actor,
    plan.cancellation_reason,
    plan.cancelled_at,
    plan.refund_eligibility,
    'STANDARD_48_HOUR',
    1,
    1,
    jsonb_build_object(
        'snapshotVersion', 1,
        'tourId', tour.id,
        'title', tour.title,
        'description', tour.description,
        'coverMediaId', tour.cover_media_id,
        'guideId', guide.id,
        'guideDisplayName', trim(guide.first_name || ' ' || guide.last_name),
        'guideAvatarMediaId', guide.avatar_media_id,
        'countryCode', tour.country_code,
        'cityPlaceId', tour.city_place_id,
        'cityName', tour.city_name,
        'timeZoneId', tour.time_zone_id,
        'categoryCode', tour.category_code,
        'languageCodes', (select jsonb_agg(language_code order by language_code)
                          from tour_languages where tour_id = tour.id),
        'sessionId', session.id,
        'startsAt', session.starts_at,
        'durationMinutes', session.duration_minutes,
        'meetingPoint', session.meeting_point,
        'unitPriceMinor', session.price_minor,
        'totalPriceMinor', session.price_minor * plan.participant_count,
        'currencyCode', 'USD',
        'participantCount', plan.participant_count,
        'cancellationPolicyCode', 'STANDARD_48_HOUR',
        'cancellationPolicyVersion', 1
    ),
    'demo-booking-' || plan.reservation_index,
    case when plan.status = 'CANCELLED' then 'demo-cancel-' || plan.reservation_index end,
    plan.active_guard,
    case when plan.status = 'CONFIRMED' and plan.reservation_index % 4 = 0 then
        current_setting('guidemate.demo_reference_instant')::timestamptz - interval '1 hour'
    end,
    0,
    case
        when plan.status = 'COMPLETED' then session.starts_at - interval '30 days'
        when plan.status = 'EXPIRED' then plan.hold_expires_at - interval '15 minutes'
        else current_setting('guidemate.demo_reference_instant')::timestamptz - interval '20 days'
            + (plan.reservation_index % 400) * interval '1 hour'
    end,
    coalesce(
        plan.cancelled_at,
        case when plan.status = 'COMPLETED' then session.starts_at + interval '1 day'
             else current_setting('guidemate.demo_reference_instant')::timestamptz - interval '1 hour' end
    )
from demo_reservation_plan plan
join tour_sessions session on session.id = pg_temp.demo_uuid('session-' || plan.session_number)
join tours tour on tour.id = session.tour_id
join users guide on guide.id = tour.guide_id;

create temporary table demo_review_plan on commit drop as
with ranked as (
    select
        reservation.id as reservation_id,
        tour.guide_id,
        row_number() over (
            partition by tour.guide_id
            order by reservation.created_at, reservation.id
        )::integer as guide_review_number
    from reservations reservation
    join tour_sessions session on session.id = reservation.session_id
    join tours tour on tour.id = session.tour_id
    where reservation.status = 'COMPLETED'
)
select *
from ranked
where guide_review_number <= case
    when guide_id between 2006 and 2035 then 8
    when guide_id between 2036 and 2045 then 5
    when guide_id between 2046 and 2049 then 20
    when guide_id = 2050 then 50
    else 0
end;

insert into reviews (id, reservation_id, rating, comment, created_at, updated_at)
select
    pg_temp.demo_uuid('review-' || reservation_id),
    reservation_id,
    case
        when guide_id = 2050 then case when guide_review_number % 25 = 0 then 4 else 5 end
        when guide_id between 2046 and 2049 then case when guide_review_number % 3 = 0 then 4 else 5 end
        when guide_id between 2036 and 2045 then case when guide_review_number = 1 then 3 else 4 end
        else case when guide_review_number % 4 = 0 then 4 else 3 end
    end,
    case when guide_review_number % 3 = 0 then null else
        (array[
            'Rota çok dengeliydi, rehberin yerel anlatımları geziyi daha anlamlı kıldı.',
            'Buluşma noktası kolay bulundu ve program tam zamanında ilerledi.',
            'Rehber sorularımızı sabırla yanıtladı, keyifli bir deneyimdi.',
            'Tarihî ayrıntılar ve küçük hikâyeler sayesinde bölgeyi yakından tanıdık.',
            'Fotoğraf molaları ve yürüyüş temposu grubumuz için gayet uygundu.',
            'Rota iyi planlanmıştı, kalabalıktan uzak durakları özellikle sevdik.',
            'Samimi, bilgili ve iletişimi güçlü bir rehberle güzel bir tur yaptık.',
            'Yerel lezzetler ve kültürel bilgiler turu beklediğimizden daha zengin yaptı.',
            'Ailece katıldık; anlatım ve tempo herkes için uygundu.',
            'Tur boyunca kendimizi güvende ve rahat hissettik, yeniden katılmak isteriz.',
            'Güzergâh açıkça anlatıldı ve her durakta yeterli zaman verildi.',
            'Bölgeyi ilk kez gezenler için bilgilendirici ve akıcı bir deneyimdi.'
        ])[1 + ((guide_review_number - 1) % 12)]
    end,
    reservation.updated_at + interval '2 days',
    reservation.updated_at + interval '2 days'
from demo_review_plan review_plan
join reservations reservation on reservation.id = review_plan.reservation_id;

create temporary table demo_successful_booking_plan on commit drop as
select
    plan.reservation_index,
    reservation.id as reservation_id,
    reservation.tourist_id,
    reservation.total_price_minor,
    reservation.created_at,
    reservation.updated_at,
    reservation.status,
    reservation.cancellation_refund_eligibility,
    session.id as session_id,
    session.starts_at,
    session.duration_minutes,
    tour.guide_id
from demo_reservation_plan plan
join reservations reservation
    on reservation.id = pg_temp.demo_uuid('reservation-' || plan.reservation_index)
join tour_sessions session on session.id = reservation.session_id
join tours tour on tour.id = session.tour_id
where reservation.status in ('COMPLETED', 'CONFIRMED')
   or (
       reservation.status = 'CANCELLED'
       and reservation.cancellation_refund_eligibility <> 'NOT_APPLICABLE'
   );

insert into payments (
    id, user_id, purpose, method, reservation_id, amount_minor, currency_code,
    status, provider, provider_payment_id, provider_transaction_id,
    provider_token_encrypted, provider_token_fingerprint,
    provider_conversation_id, payment_page_url, idempotency_key, expires_at,
    verified_at, failure_code, version, created_at, updated_at,
    reconciliation_attempt_count, last_reconciliation_at,
    fx_quote_id, charge_amount_minor, charge_currency_code, fx_rate,
    fx_rate_source, fx_quoted_at
)
select
    pg_temp.demo_uuid('payment-booking-' || reservation_index),
    tourist_id,
    'TOUR_BOOKING',
    'WALLET',
    reservation_id,
    total_price_minor,
    'USD',
    'SUCCEEDED',
    null, null, null, null, null, null, null,
    'demo-payment-booking-' || reservation_index,
    null,
    created_at + interval '2 minutes',
    null,
    0,
    created_at + interval '1 minute',
    created_at + interval '2 minutes',
    0,
    null,
    null, null, null, null, null, null
from demo_successful_booking_plan;

create temporary table demo_refund_plan on commit drop as
with refundable as (
    select
        booking.reservation_index,
        booking.reservation_id,
        booking.tourist_id,
        booking.guide_id,
        booking.total_price_minor,
        reservation.cancellation_actor,
        coalesce(
            reservation.cancelled_at,
            booking.starts_at + booking.duration_minutes * interval '1 minute' + interval '3 days'
        ) as requested_at
    from demo_successful_booking_plan booking
    join reservations reservation on reservation.id = booking.reservation_id
    where reservation.cancellation_refund_eligibility = 'FULL_REFUND'
       or booking.reservation_index between 1 and 5
)
select
    row_number() over (order by reservation_index)::integer as refund_index,
    refundable.*
from refundable;

insert into refunds (
    id, payment_id, requested_by, amount_minor, currency_code, status,
    provider_refund_id, idempotency_key, failure_code, requested_at,
    completed_at, version, created_at, updated_at,
    processing_attempt_count, last_processing_attempt_at,
    charge_amount_minor, charge_currency_code
)
select
    pg_temp.demo_uuid('refund-' || refund_index),
    pg_temp.demo_uuid('payment-booking-' || reservation_index),
    case when cancellation_actor = 'GUIDE' then guide_id else tourist_id end,
    total_price_minor,
    'USD',
    'SUCCEEDED',
    'demo-refund-provider-' || refund_index,
    'demo-refund-' || refund_index,
    null,
    requested_at,
    requested_at + interval '20 minutes',
    0,
    requested_at,
    requested_at + interval '20 minutes',
    1,
    requested_at + interval '10 minutes',
    total_price_minor,
    'USD'
from demo_refund_plan;

create temporary table demo_top_up_plan on commit drop as
with purchases as (
    select tourist_id, sum(total_price_minor) as purchase_minor
    from demo_successful_booking_plan
    group by tourist_id
), refunded as (
    select tourist_id, sum(total_price_minor) as refund_minor
    from demo_refund_plan
    group by tourist_id
)
select
    purchases.tourist_id,
    purchases.purchase_minor
        - coalesce(refunded.refund_minor, 0)
        + 5000 + (purchases.tourist_id % 10) * 2500 as top_up_minor
from purchases
left join refunded using (tourist_id);

insert into payments (
    id, user_id, purpose, method, reservation_id, amount_minor, currency_code,
    status, provider, provider_payment_id, provider_transaction_id,
    provider_token_encrypted, provider_token_fingerprint,
    provider_conversation_id, payment_page_url, idempotency_key, expires_at,
    verified_at, failure_code, version, created_at, updated_at,
    reconciliation_attempt_count, last_reconciliation_at,
    fx_quote_id, charge_amount_minor, charge_currency_code, fx_rate,
    fx_rate_source, fx_quoted_at
)
select
    pg_temp.demo_uuid('payment-top-up-' || tourist_id),
    tourist_id,
    'WALLET_TOP_UP',
    'HOSTED_CARD',
    null,
    top_up_minor,
    'USD',
    'SUCCEEDED',
    'IYZICO',
    'demo-fixture-payment-' || tourist_id,
    'demo-fixture-transaction-' || tourist_id,
    null,
    null,
    'demo-fixture-conversation-' || tourist_id,
    null,
    'demo-top-up-' || tourist_id,
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '12 months'
        + (tourist_id % 120) * interval '1 day' + interval '30 minutes',
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '12 months'
        + (tourist_id % 120) * interval '1 day',
    null,
    0,
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '12 months'
        + (tourist_id % 120) * interval '1 day',
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '12 months'
        + (tourist_id % 120) * interval '1 day',
    0,
    null,
    null,
    top_up_minor,
    'USD',
    1.000000000000,
    'DEMO_HISTORICAL_USD',
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '12 months'
        + (tourist_id % 120) * interval '1 day'
from demo_top_up_plan;

insert into payments (
    id, user_id, purpose, method, reservation_id, amount_minor, currency_code,
    status, provider, provider_payment_id, provider_transaction_id,
    provider_token_encrypted, provider_token_fingerprint,
    provider_conversation_id, payment_page_url, idempotency_key, expires_at,
    verified_at, failure_code, version, created_at, updated_at,
    reconciliation_attempt_count, last_reconciliation_at,
    fx_quote_id, charge_amount_minor, charge_currency_code, fx_rate,
    fx_rate_source, fx_quoted_at
)
select
    pg_temp.demo_uuid('payment-unsuccessful-top-up-' || number),
    1231 + ((number - 1) % 20),
    'WALLET_TOP_UP',
    'HOSTED_CARD',
    null,
    10000 + number * 500,
    'USD',
    case when number <= 10 then 'FAILED' else 'CANCELLED' end,
    'IYZICO',
    'demo-unsuccessful-payment-' || number,
    null,
    null,
    null,
    'demo-unsuccessful-conversation-' || number,
    null,
    'demo-unsuccessful-top-up-' || number,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (30 - number) * interval '1 day' + interval '30 minutes',
    null,
    case when number <= 10 then 'PROVIDER_DECLINED' else 'USER_CANCELLED' end,
    0,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (30 - number) * interval '1 day',
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (30 - number) * interval '1 day' + interval '10 minutes',
    0,
    null,
    null,
    10000 + number * 500,
    'USD',
    1.000000000000,
    'DEMO_HISTORICAL_USD',
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (30 - number) * interval '1 day'
from generate_series(1, 15) number;

insert into wallet_ledger_entries (
    id, wallet_id, direction, type, amount_minor, reference_type,
    reference_id, idempotency_key, occurred_at, created_at
)
select
    pg_temp.demo_uuid('ledger-top-up-' || tourist_id),
    pg_temp.demo_uuid('wallet-' || tourist_id),
    'CREDIT',
    'TOP_UP',
    top_up_minor,
    'PAYMENT',
    pg_temp.demo_uuid('payment-top-up-' || tourist_id),
    'demo-ledger-top-up-' || tourist_id,
    payment.verified_at,
    payment.verified_at
from demo_top_up_plan
join payments payment on payment.id = pg_temp.demo_uuid('payment-top-up-' || tourist_id);

insert into wallet_ledger_entries (
    id, wallet_id, direction, type, amount_minor, reference_type,
    reference_id, idempotency_key, occurred_at, created_at
)
select
    pg_temp.demo_uuid('ledger-purchase-' || reservation_index),
    pg_temp.demo_uuid('wallet-' || tourist_id),
    'DEBIT',
    'TOUR_PURCHASE',
    total_price_minor,
    'PAYMENT',
    pg_temp.demo_uuid('payment-booking-' || reservation_index),
    'demo-ledger-purchase-' || reservation_index,
    created_at + interval '2 minutes',
    created_at + interval '2 minutes'
from demo_successful_booking_plan;

insert into wallet_ledger_entries (
    id, wallet_id, direction, type, amount_minor, reference_type,
    reference_id, idempotency_key, occurred_at, created_at
)
select
    pg_temp.demo_uuid('ledger-refund-' || refund_index),
    pg_temp.demo_uuid('wallet-' || tourist_id),
    'CREDIT',
    'REFUND',
    total_price_minor,
    'REFUND',
    pg_temp.demo_uuid('refund-' || refund_index),
    'demo-ledger-refund-' || refund_index,
    requested_at + interval '20 minutes',
    requested_at + interval '20 minutes'
from demo_refund_plan;

insert into guide_earnings (
    id, reservation_id, gross_minor, platform_fee_minor, net_minor,
    currency_code, status, available_at, reversed_at, version,
    created_at, updated_at
)
select
    pg_temp.demo_uuid('earning-' || reservation_index),
    reservation_id,
    total_price_minor,
    total_price_minor * 1000 / 10000,
    total_price_minor - total_price_minor * 1000 / 10000,
    'USD',
    case
        when reservation_index between 1 and 5 then 'REVERSED'
        when status = 'COMPLETED' then 'AVAILABLE'
        when status = 'CANCELLED' and cancellation_refund_eligibility = 'FULL_REFUND' then 'REVERSED'
        else 'PENDING'
    end,
    starts_at + duration_minutes * interval '1 minute',
    case
        when reservation_index between 1 and 5 then
            starts_at + duration_minutes * interval '1 minute' + interval '3 days'
        when status = 'CANCELLED' and cancellation_refund_eligibility = 'FULL_REFUND' then updated_at
    end,
    0,
    created_at + interval '3 minutes',
    case
        when status = 'COMPLETED' then starts_at + duration_minutes * interval '1 minute'
        else updated_at
    end
from demo_successful_booking_plan;

insert into wallet_ledger_entries (
    id, wallet_id, direction, type, amount_minor, reference_type,
    reference_id, idempotency_key, occurred_at, created_at
)
select
    pg_temp.demo_uuid('ledger-earning-' || reservation_index),
    pg_temp.demo_uuid('wallet-' || guide_id),
    'CREDIT',
    'GUIDE_EARNING',
    total_price_minor - total_price_minor * 1000 / 10000,
    'GUIDE_EARNING',
    pg_temp.demo_uuid('earning-' || reservation_index),
    'demo-ledger-earning-' || reservation_index,
    starts_at + duration_minutes * interval '1 minute',
    starts_at + duration_minutes * interval '1 minute'
from demo_successful_booking_plan
where status = 'COMPLETED';

insert into wallet_ledger_entries (
    id, wallet_id, direction, type, amount_minor, reference_type,
    reference_id, idempotency_key, occurred_at, created_at
)
select
    pg_temp.demo_uuid('ledger-earning-reversal-' || reservation_index),
    pg_temp.demo_uuid('wallet-' || guide_id),
    'DEBIT',
    'EARNING_REVERSAL',
    total_price_minor - total_price_minor * 1000 / 10000,
    'GUIDE_EARNING',
    pg_temp.demo_uuid('earning-' || reservation_index),
    'demo-ledger-earning-reversal-' || reservation_index,
    starts_at + duration_minutes * interval '1 minute' + interval '3 days',
    starts_at + duration_minutes * interval '1 minute' + interval '3 days'
from demo_successful_booking_plan
where reservation_index between 1 and 5;

insert into bank_accounts (
    id, guide_id, iban_encrypted, iban_fingerprint, masked_iban, bank_code,
    bank_name, account_holder_name, is_default, default_guard, status,
    version, created_at, updated_at
)
select
    id,
    guide_id,
    iban_encrypted,
    iban_fingerprint,
    masked_iban,
    bank_code,
    bank_name,
    account_holder_name,
    ordinal = 1,
    case when ordinal = 1 then true end,
    case when ordinal = 2 and guide_id between 2011 and 2015 then 'DISABLED' else 'ACTIVE' end,
    0,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (2051 - guide_id) * interval '4 days' + ordinal * interval '1 hour',
    current_setting('guidemate.demo_reference_instant')::timestamptz - interval '3 days'
from demo_bank_fixture;

insert into withdrawals (
    id, wallet_id, bank_account_id, amount_minor, currency_code, status,
    payout_mode, idempotency_key, provider_reference, failure_code,
    requested_at, completed_at, version, created_at, updated_at
)
select
    pg_temp.demo_uuid('withdrawal-' || number),
    pg_temp.demo_uuid('wallet-' || (2005 + number)),
    bank.id,
    1000 + (number % 5) * 500,
    'USD',
    'COMPLETED',
    'SIMULATED',
    'demo-withdrawal-' || number,
    'SIMULATED-DEMO-' || lpad(number::text, 3, '0'),
    null,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (31 - number) * interval '5 days',
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (31 - number) * interval '5 days' + interval '1 minute',
    0,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (31 - number) * interval '5 days',
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (31 - number) * interval '5 days' + interval '1 minute'
from generate_series(1, 30) number
join bank_accounts bank on bank.guide_id = 2005 + number and bank.is_default;

insert into wallet_ledger_entries (
    id, wallet_id, direction, type, amount_minor, reference_type,
    reference_id, idempotency_key, occurred_at, created_at
)
select
    pg_temp.demo_uuid('ledger-withdrawal-' || number),
    pg_temp.demo_uuid('wallet-' || (2005 + number)),
    'DEBIT',
    'WITHDRAWAL',
    1000 + (number % 5) * 500,
    'WITHDRAWAL',
    pg_temp.demo_uuid('withdrawal-' || number),
    'demo-ledger-withdrawal-' || number,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (31 - number) * interval '5 days' + interval '1 minute',
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (31 - number) * interval '5 days' + interval '1 minute'
from generate_series(1, 30) number;

create temporary table demo_conversation_plan on commit drop as
select
    number as conversation_index,
    pg_temp.demo_uuid('conversation-' || number) as conversation_id,
    2001 + ((number - 1) % 50) as guide_id,
    1026 + ((number - 1) % 225) as tourist_id,
    case
        when number = 1 then 0
        when number = 2 then 1
        when number = 3 then 60
        when number <= 41 then 14
        else 13
    end as message_count,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (181 - number) * interval '12 hours' as started_at
from generate_series(1, 180) number;

insert into chat_conversations (id, guide_id, tourist_id, created_at, updated_at)
select
    conversation_id,
    guide_id,
    tourist_id,
    started_at,
    started_at
from demo_conversation_plan;

create temporary table demo_message_plan on commit drop as
select
    conversation.conversation_index,
    conversation.conversation_id,
    conversation.guide_id,
    conversation.tourist_id,
    conversation.message_count,
    message_index,
    pg_temp.demo_uuid(
        'message-' || conversation.conversation_index || '-' || message_index
    ) as message_id,
    case
        when message_index % 2 = 1 then conversation.tourist_id
        else conversation.guide_id
    end as sender_id,
    conversation.started_at + message_index * interval '3 minutes' as sent_at
from demo_conversation_plan conversation
cross join lateral generate_series(1, conversation.message_count) message_index;

insert into chat_messages (
    id, conversation_id, sender_id, client_message_id, body, sent_at
)
select
    message_id,
    conversation_id,
    sender_id,
    pg_temp.demo_uuid('client-message-' || conversation_index || '-' || message_index),
    case message_index % 8
        when 0 then 'Teşekkür ederim, bu rota grubumuz için çok uygun görünüyor.'
        when 1 then 'Merhaba, bu deneyim bölgeyi ilk kez ziyaret edenler için uygun mu?'
        when 2 then 'Evet. Yürüyüş temposunu gruba göre ayarlayıp her durağı ayrıntılı anlatabilirim.'
        when 3 then 'Tur başlamadan önce tam olarak nerede buluşacağız?'
        when 4 then 'Ana ziyaretçi girişindeki işaretli tabelanın yanında buluşacağız.'
        when 5 then 'Rota sırasında soru sorabilir ve fotoğraf çekebilir miyiz?'
        when 6 then 'Elbette. Fotoğraf çekmek ve soru sormak için planlı molalarımız olacak.'
        else 'Harika, ayrıntıları gezi planımıza ekledim. Görüşmek üzere.'
    end,
    sent_at
from demo_message_plan;

update chat_conversations conversation
set updated_at = message.last_sent_at
from (
    select conversation_id, max(sent_at) as last_sent_at
    from demo_message_plan
    group by conversation_id
) message
where conversation.id = message.conversation_id;

insert into chat_read_state (
    conversation_id, user_id, last_read_message_id, read_at
)
select
    conversation.conversation_id,
    participant.user_id,
    last_read.message_id,
    coalesce(last_read.sent_at, conversation.started_at)
from demo_conversation_plan conversation
cross join lateral (
    values
        (conversation.guide_id, conversation.conversation_index % 4),
        (conversation.tourist_id, (conversation.conversation_index + 1) % 5)
) participant(user_id, unread_count)
left join lateral (
    select message.message_id, message.sent_at
    from demo_message_plan message
    where message.conversation_id = conversation.conversation_id
      and message.message_index <= greatest(
          conversation.message_count - participant.unread_count,
          0
      )
    order by message.message_index desc
    limit 1
) last_read on true;

create temporary table demo_notification_plan on commit drop as
with notification_types as (
    select array[
        'TOUR_APPROVED', 'TOUR_REJECTED', 'TOUR_CHANGE_APPROVED',
        'TOUR_CHANGE_REJECTED', 'TOUR_PURCHASED', 'RESERVATION_CONFIRMED',
        'RESERVATION_CANCELLED', 'TOUR_CANCELLED', 'TOUR_COMPLETED',
        'REVIEW_REQUEST', 'RATING_RECEIVED', 'COMMENT_RECEIVED',
        'PAYMENT_SUCCEEDED', 'PAYMENT_FAILED', 'REFUND_REQUESTED',
        'REFUND_COMPLETED', 'REFUND_FAILED', 'REFUND_MANUAL_REVIEW',
        'EARNING_AVAILABLE', 'WITHDRAWAL_COMPLETED', 'CHAT_MESSAGE',
        'UPCOMING_TOUR_REMINDER', 'SECURITY_ALERT'
    ]::varchar[] as values
), plan as (
    select
        number as notification_index,
        case
            when number <= 750 then 1001 + ((number - 1) % 250)
            when number <= 900 then 2001 + ((number - 751) % 50)
            when number <= 1100 then 1231 + ((number - 901) % 20)
            else 2046 + ((number - 1101) / 20)
        end as recipient_id,
        case
            when number > 900 then 'SECURITY_ALERT'
            else types.values[1 + ((number - 1) % 23)]
        end as type
    from generate_series(1, 1200) number
    cross join notification_types types
)
select
    plan.*,
    1 + ((notification_index - 1) % 180) as tour_index,
    1 + ((notification_index - 1) % 1230) as booking_rank,
    1 + ((notification_index - 1) % 850) as completed_reservation_index,
    851 + ((notification_index - 1) % 300) as confirmed_reservation_index,
    1211 + ((notification_index - 1) % 90) as cancelled_reservation_index,
    1 + ((notification_index - 1) % 420) as review_rank,
    1 + ((notification_index - 1) % 65) as refund_index,
    1 + ((notification_index - 1) % 30) as withdrawal_index,
    1 + ((notification_index - 1) % 180) as conversation_index,
    current_setting('guidemate.demo_reference_instant')::timestamptz
        - (1201 - notification_index) * interval '2 hours' as created_at
from plan;

insert into notifications (
    id, recipient_id, type, actor_id, payload, read_at, push_status,
    last_push_attempt_at, deduplication_key, push_attempt_count,
    next_push_attempt_at, created_at
)
select
    pg_temp.demo_uuid('notification-' || notification.notification_index),
    routing.recipient_id,
    notification.type,
    routing.actor_id,
    jsonb_strip_nulls(
        case
            when notification.type in (
                'TOUR_APPROVED', 'TOUR_REJECTED',
                'TOUR_CHANGE_APPROVED', 'TOUR_CHANGE_REJECTED'
            ) then jsonb_build_object(
                'tourId', moderation_tour.id,
                'reviewId', pg_temp.demo_uuid(
                    case
                        when notification.type = 'TOUR_CHANGE_APPROVED' then
                            'tour-change-' || (11 + ((notification.notification_index - 1) % 10))
                        when notification.type = 'TOUR_CHANGE_REJECTED' then
                            'tour-change-' || (21 + ((notification.notification_index - 1) % 10))
                        else 'tour-review-' || notification.notification_index
                    end
                ),
                'tourTitle', moderation_tour.title,
                'rejectionReason', case when notification.type in ('TOUR_REJECTED', 'TOUR_CHANGE_REJECTED')
                    then 'Rota ayrıntılarının onaydan önce biraz netleştirilmesi gerekiyor.' end
            )
            when notification.type = 'TOUR_PURCHASED' then jsonb_build_object(
                'reservationId', booking.reservation_id,
                'sessionId', booking.session_id,
                'tourId', booking_tour.id,
                'tourTitle', booking_tour.title,
                'participantCount', booking_reservation.participant_count,
                'amountMinor', booking.total_price_minor,
                'currencyCode', booking_reservation.currency_code
            )
            when notification.type = 'RESERVATION_CONFIRMED' then jsonb_build_object(
                'reservationId', confirmed_reservation.id,
                'sessionId', confirmed_reservation.session_id,
                'tourId', confirmed_tour.id,
                'tourTitle', confirmed_tour.title,
                'participantCount', confirmed_reservation.participant_count,
                'amountMinor', confirmed_reservation.total_price_minor,
                'currencyCode', confirmed_reservation.currency_code
            )
            when notification.type = 'RESERVATION_CANCELLED' then jsonb_build_object(
                'reservationId', cancelled_reservation.id,
                'sessionId', cancelled_reservation.session_id,
                'tourId', cancelled_tour.id,
                'tourTitle', cancelled_tour.title,
                'participantCount', cancelled_reservation.participant_count,
                'amountMinor', cancelled_reservation.total_price_minor,
                'currencyCode', cancelled_reservation.currency_code
            )
            when notification.type in ('TOUR_CANCELLED', 'TOUR_COMPLETED', 'UPCOMING_TOUR_REMINDER')
                then jsonb_build_object(
                    'sessionId', lifecycle_session.id,
                    'tourId', lifecycle_tour.id,
                    'tourTitle', lifecycle_tour.title,
                    'startsAt', lifecycle_session.starts_at
                )
            when notification.type = 'REVIEW_REQUEST' then jsonb_build_object(
                'reservationId', completed_reservation.id,
                'tourId', completed_tour.id,
                'tourTitle', completed_tour.title
            )
            when notification.type in ('RATING_RECEIVED', 'COMMENT_RECEIVED') then jsonb_build_object(
                'reviewId', review_context.review_id,
                'tourId', review_context.tour_id,
                'tourTitle', review_context.tour_title,
                'rating', review_context.rating,
                'commentPreview', left(review_context.comment, 120)
            )
            when notification.type = 'PAYMENT_SUCCEEDED' then jsonb_build_object(
                'paymentId', pg_temp.demo_uuid('payment-booking-' || booking.reservation_index),
                'reservationId', booking.reservation_id,
                'amountMinor', booking.total_price_minor,
                'currencyCode', 'USD'
            )
            when notification.type = 'PAYMENT_FAILED' then jsonb_build_object(
                'paymentId', failed_payment.id,
                'amountMinor', failed_payment.amount_minor,
                'currencyCode', failed_payment.currency_code
            )
            when notification.type in (
                'REFUND_REQUESTED', 'REFUND_COMPLETED',
                'REFUND_FAILED', 'REFUND_MANUAL_REVIEW'
            ) then jsonb_build_object(
                'refundId', pg_temp.demo_uuid('refund-' || notification.refund_index),
                'paymentId', refund.payment_id,
                'amountMinor', refund.amount_minor,
                'currencyCode', 'USD'
            )
            when notification.type = 'EARNING_AVAILABLE' then jsonb_build_object(
                'earningId', pg_temp.demo_uuid('earning-' || booking.reservation_index),
                'reservationId', booking.reservation_id,
                'amountMinor', earning.net_minor,
                'currencyCode', earning.currency_code,
                'tourTitle', booking_tour.title
            )
            when notification.type = 'WITHDRAWAL_COMPLETED' then jsonb_build_object(
                'withdrawalId', pg_temp.demo_uuid('withdrawal-' || notification.withdrawal_index),
                'amountMinor', withdrawal.amount_minor,
                'currencyCode', withdrawal.currency_code
            )
            when notification.type = 'CHAT_MESSAGE' then jsonb_build_object(
                'chatId', conversation.id,
                'messageId', coalesce(message.message_id, pg_temp.demo_uuid('message-2-1')),
                'senderId', routing.actor_id,
                'senderName', actor.first_name || ' ' || actor.last_name,
                'messagePreview', 'GuideMate sohbetinizde yeni bir mesaj sizi bekliyor.'
            )
            else jsonb_build_object('securityEvent', 'DEMO_ACCOUNT_ACTIVITY')
        end
    ),
    case when notification.notification_index % 2 = 0
        then notification.created_at + interval '30 minutes' end,
    'NOT_REQUESTED',
    null,
    'demo-notification-' || notification.notification_index,
    0,
    null,
    notification.created_at
from demo_notification_plan notification
left join lateral (
    select candidate.*
    from demo_successful_booking_plan candidate
    order by candidate.reservation_index
    offset notification.booking_rank - 1
    limit 1
) booking on true
left join reservations booking_reservation on booking_reservation.id = booking.reservation_id
left join tour_sessions booking_session on booking_session.id = booking.session_id
left join tours booking_tour on booking_tour.id = booking_session.tour_id
left join reservations completed_reservation
    on completed_reservation.id = pg_temp.demo_uuid(
        'reservation-' || notification.completed_reservation_index
    )
left join tour_sessions completed_session on completed_session.id = completed_reservation.session_id
left join tours completed_tour on completed_tour.id = completed_session.tour_id
left join reservations confirmed_reservation
    on confirmed_reservation.id = pg_temp.demo_uuid(
        'reservation-' || notification.confirmed_reservation_index
    )
left join tour_sessions confirmed_session on confirmed_session.id = confirmed_reservation.session_id
left join tours confirmed_tour on confirmed_tour.id = confirmed_session.tour_id
left join reservations cancelled_reservation
    on cancelled_reservation.id = pg_temp.demo_uuid(
        'reservation-' || notification.cancelled_reservation_index
    )
left join tour_sessions cancelled_session on cancelled_session.id = cancelled_reservation.session_id
left join tours cancelled_tour on cancelled_tour.id = cancelled_session.tour_id
left join tour_sessions lifecycle_session on lifecycle_session.id = case
    when notification.type = 'TOUR_CANCELLED' then pg_temp.demo_uuid(
        'session-' || (541 + ((notification.notification_index - 1) % 20))
    )
    when notification.type = 'TOUR_COMPLETED' then pg_temp.demo_uuid(
        'session-' || (1 + ((notification.notification_index - 1) % 365))
    )
    when notification.type = 'UPCOMING_TOUR_REMINDER' then confirmed_reservation.session_id
end
left join tours lifecycle_tour on lifecycle_tour.id = lifecycle_session.tour_id
left join tours moderation_tour on moderation_tour.id = pg_temp.demo_uuid(
    'tour-' || case
        when notification.type = 'TOUR_APPROVED'
            then 1 + ((notification.notification_index - 1) % 130)
        when notification.type = 'TOUR_REJECTED'
            then 151 + ((notification.notification_index - 1) % 15)
        when notification.type = 'TOUR_CHANGE_APPROVED'
            then 11 + ((notification.notification_index - 1) % 10)
        when notification.type = 'TOUR_CHANGE_REJECTED'
            then 21 + ((notification.notification_index - 1) % 10)
    end
)
left join lateral (
    select
        review.id as review_id,
        review.rating,
        review.comment,
        reservation.tourist_id,
        tour.id as tour_id,
        tour.guide_id,
        tour.title as tour_title
    from reviews review
    join reservations reservation on reservation.id = review.reservation_id
    join tour_sessions session on session.id = reservation.session_id
    join tours tour on tour.id = session.tour_id
    order by review.id
    offset notification.review_rank - 1
    limit 1
) review_context on true
left join refunds refund
    on refund.id = pg_temp.demo_uuid('refund-' || notification.refund_index)
left join payments refund_payment on refund_payment.id = refund.payment_id
left join payments failed_payment on failed_payment.id = pg_temp.demo_uuid(
    'payment-unsuccessful-top-up-' || (1 + ((notification.notification_index - 1) % 10))
)
left join guide_earnings earning
    on earning.id = pg_temp.demo_uuid('earning-' || booking.reservation_index)
left join withdrawals withdrawal
    on withdrawal.id = pg_temp.demo_uuid('withdrawal-' || notification.withdrawal_index)
left join wallets withdrawal_wallet on withdrawal_wallet.id = withdrawal.wallet_id
left join chat_conversations conversation
    on conversation.id = pg_temp.demo_uuid('conversation-' || notification.conversation_index)
left join lateral (
    select candidate.message_id
    from demo_message_plan candidate
    where candidate.conversation_index = notification.conversation_index
    order by candidate.message_index desc
    limit 1
) message on true
left join lateral (
    select
        case
            when notification.type in (
                'TOUR_APPROVED', 'TOUR_REJECTED',
                'TOUR_CHANGE_APPROVED', 'TOUR_CHANGE_REJECTED'
            ) then moderation_tour.guide_id
            when notification.type = 'TOUR_PURCHASED' then booking.guide_id
            when notification.type = 'RESERVATION_CONFIRMED' then confirmed_reservation.tourist_id
            when notification.type = 'RESERVATION_CANCELLED' then cancelled_reservation.tourist_id
            when notification.type in ('TOUR_CANCELLED', 'TOUR_COMPLETED') then lifecycle_tour.guide_id
            when notification.type = 'REVIEW_REQUEST' then completed_reservation.tourist_id
            when notification.type in ('RATING_RECEIVED', 'COMMENT_RECEIVED') then review_context.guide_id
            when notification.type = 'PAYMENT_SUCCEEDED' then booking.tourist_id
            when notification.type = 'PAYMENT_FAILED' then failed_payment.user_id
            when notification.type in (
                'REFUND_REQUESTED', 'REFUND_COMPLETED',
                'REFUND_FAILED', 'REFUND_MANUAL_REVIEW'
            ) then refund_payment.user_id
            when notification.type = 'EARNING_AVAILABLE' then booking.guide_id
            when notification.type = 'WITHDRAWAL_COMPLETED' then withdrawal_wallet.user_id
            when notification.type = 'CHAT_MESSAGE' then case
                when notification.notification_index % 2 = 0 then conversation.guide_id
                else conversation.tourist_id
            end
            when notification.type = 'UPCOMING_TOUR_REMINDER' then confirmed_reservation.tourist_id
            else notification.recipient_id
        end as recipient_id,
        case
            when notification.type in (
                'TOUR_APPROVED', 'TOUR_REJECTED',
                'TOUR_CHANGE_APPROVED', 'TOUR_CHANGE_REJECTED'
            ) then 3001
            when notification.type = 'TOUR_PURCHASED' then booking.tourist_id
            when notification.type in ('RATING_RECEIVED', 'COMMENT_RECEIVED')
                then review_context.tourist_id
            when notification.type = 'CHAT_MESSAGE' then case
                when notification.notification_index % 2 = 0 then conversation.tourist_id
                else conversation.guide_id
            end
        end as actor_id
) routing on true
left join users actor on actor.id = routing.actor_id;

analyze users;
analyze tours;
analyze tour_sessions;
analyze reservations;
analyze payments;
analyze wallet_ledger_entries;
analyze chat_messages;
analyze notifications;
