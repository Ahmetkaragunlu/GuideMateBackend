package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Component
class DemoDatasetVerifier {

    private static final int EXPECTED_SEEDED_USER_COUNT = 306;

    private final JdbcTemplate jdbcTemplate;

    DemoDatasetVerifier(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    boolean isAlreadySeeded() {
        long seededUsers = count("""
                select count(*)
                from users
                where email like '%@demo.guidemate.test'
                """);
        if (seededUsers == 0) {
            return false;
        }
        if (seededUsers != EXPECTED_SEEDED_USER_COUNT) {
            throw new IllegalStateException("The demo database contains a partial dataset");
        }
        return true;
    }

    void requireEmptyTarget() {
        assertCount("users", 0, "select count(*) from users");
        assertCount("media assets", 0, "select count(*) from media_assets");
        assertCount("tours", 0, "select count(*) from tours");
        assertCount("reservations", 0, "select count(*) from reservations");
        assertCount("payments", 0, "select count(*) from payments");
        assertCount("chat conversations", 0, "select count(*) from chat_conversations");
        assertCount("notifications", 0, "select count(*) from notifications");
    }

    void verify(Instant referenceInstant) {
        Objects.requireNonNull(referenceInstant);
        verifyPopulation();
        verifyTourAndReservationLifecycle();
        verifyFinance();
        verifyCommunication();
        verifyDerivedInvariants(referenceInstant);
    }

    private void verifyPopulation() {
        assertCount("seeded users", 306, """
                select count(*) from users where email like '%@demo.guidemate.test'
                """);
        assertCount("active tourists", 250, """
                select count(*)
                from users user_account
                join roles role on role.id = user_account.role_id
                where user_account.id between 1001 and 1250
                  and user_account.account_status = 'ACTIVE'
                  and user_account.role_selected
                  and role.name = 'ROLE_TOURIST'
                """);
        assertCount("active guides", 50, """
                select count(*)
                from users user_account
                join roles role on role.id = user_account.role_id
                where user_account.id between 2001 and 2050
                  and user_account.account_status = 'ACTIVE'
                  and user_account.role_selected
                  and role.name = 'ROLE_GUIDE'
                """);
        assertCount("duplicate primary demo surnames", 0, """
                select count(*)
                from (
                    select last_name
                    from users
                    where id between 1001 and 1250 or id between 2001 and 2050
                    group by last_name
                    having count(*) > 1
                ) duplicate_surname
                """);
        assertCount("guide profiles", 50, "select count(*) from guide_profiles");
        assertCount("user avatars", 300, """
                select count(*)
                from users
                where (id between 1001 and 1250 or id between 2001 and 2050)
                  and avatar_media_id is not null
                """);
        assertCount("demo media assets", 480, """
                select count(*) from media_assets where storage_key like 'seed-v1/%'
                """);
        assertCount("tour covers", 180, """
                select count(*)
                from tours tour
                join media_assets media on media.id = tour.cover_media_id
                where media.purpose = 'TOUR_COVER'
                  and media.owner_user_id = tour.guide_id
                  and media.status = 'READY'
                """);
    }

    private void verifyTourAndReservationLifecycle() {
        assertCount("tours", 180, "select count(*) from tours");
        assertCount("demo tours outside Turkey", 0, """
                select count(*)
                from tours
                where country_code <> 'TR' or time_zone_id <> 'Europe/Istanbul'
                """);
        assertCount("demo tours without Turkish language", 0, """
                select count(*)
                from tours tour
                where not exists (
                    select 1
                    from tour_languages language
                    where language.tour_id = tour.id and language.language_code = 'tr'
                )
                """);
        assertCount("non-Turkish demo tour text", 0, """
                select count(*)
                from tours
                where title !~ '[çğıöşüÇĞİÖŞÜ]'
                   or description !~ '[çğıöşüÇĞİÖŞÜ]'
                """);
        assertGroupedCounts(
                "tour approval statuses",
                "select approval_status, count(*) from tours group by approval_status",
                Map.of("APPROVED", 130L, "PENDING_REVIEW", 20L, "REJECTED", 15L, "ARCHIVED", 15L)
        );
        assertCount("tour sessions", 560, "select count(*) from tour_sessions");
        assertGroupedCounts(
                "tour session statuses",
                "select status, count(*) from tour_sessions group by status",
                Map.of("COMPLETED", 365L, "OPEN_FOR_BOOKING", 150L, "CLOSED", 25L, "CANCELLED", 20L)
        );
        assertCount("tour change requests", 30, "select count(*) from tour_change_requests");
        assertGroupedCounts(
                "tour change request statuses",
                "select status, count(*) from tour_change_requests group by status",
                Map.of("PENDING", 10L, "APPROVED", 10L, "REJECTED", 10L)
        );
        assertCount("reservations", 1300, "select count(*) from reservations");
        assertGroupedCounts(
                "reservation statuses",
                "select status, count(*) from reservations group by status",
                Map.of(
                        "COMPLETED", 850L,
                        "CONFIRMED", 300L,
                        "PENDING_PAYMENT", 20L,
                        "EXPIRED", 40L,
                        "CANCELLED", 90L
                )
        );
        assertCount("reviews", 420, "select count(*) from reviews");
        assertCount("non-Turkish written reviews", 0, """
                select count(*)
                from reviews
                where comment is not null
                  and comment !~ '[çğıöşüÇĞİÖŞÜ]'
                """);
        assertCount("reviews outside completed reservations", 0, """
                select count(*)
                from reviews review
                join reservations reservation on reservation.id = review.reservation_id
                where reservation.status <> 'COMPLETED'
                """);
        assertCount("reservation price mismatches", 0, """
                select count(*)
                from reservations reservation
                where reservation.total_price_minor
                    <> reservation.unit_price_minor * reservation.participant_count
                """);
        assertCount("unsupported reservation cancellation policies", 0, """
                select count(*)
                from reservations reservation
                where reservation.cancellation_policy_code is distinct from 'FULL_REFUND_48_HOURS'
                   or reservation.cancellation_policy_version is distinct from 1
                   or reservation.purchase_snapshot ->> 'cancellationPolicyCode'
                       is distinct from reservation.cancellation_policy_code
                   or (reservation.purchase_snapshot ->> 'cancellationPolicyVersion')::integer
                       is distinct from reservation.cancellation_policy_version
                """);
    }

    private void verifyFinance() {
        assertCount("wallets", 300, "select count(*) from wallets");
        assertCount("payments", 1435, "select count(*) from payments");
        assertCount("refunds", 65, "select count(*) from refunds");
        assertCount("wallet ledger entries", 2370, "select count(*) from wallet_ledger_entries");
        assertCount("guide earnings", 1230, "select count(*) from guide_earnings");
        assertCount("bank accounts", 55, "select count(*) from bank_accounts");
        assertCount("completed simulated withdrawals", 30, """
                select count(*)
                from withdrawals
                where status = 'COMPLETED' and payout_mode = 'SIMULATED'
                """);
        assertCount("negative wallet balances", 0, """
                select count(*)
                from (
                    select wallet.id,
                           coalesce(sum(case ledger.direction
                               when 'CREDIT' then ledger.amount_minor
                               else -ledger.amount_minor end), 0) as balance_minor
                    from wallets wallet
                    left join wallet_ledger_entries ledger on ledger.wallet_id = wallet.id
                    group by wallet.id
                ) balance
                where balance.balance_minor < 0
                """);
        assertCount("saved card fixtures", 0, "select count(*) from saved_payment_methods");
        assertCount("provider customer fixtures", 0, "select count(*) from payment_provider_customers");
        assertCount("payment event fixtures", 0, "select count(*) from payment_events");
        assertCount("foreign exchange quote fixtures", 0, "select count(*) from payment_fx_quotes");
        assertCount("plaintext bank identifiers", 0, """
                select count(*)
                from bank_accounts
                where iban_encrypted is null
                   or iban_fingerprint is null
                   or masked_iban not like 'TR__ %'
                """);
    }

    private void verifyCommunication() {
        assertCount("notification preferences", 300, "select count(*) from notification_preferences");
        assertCount("device registration fixtures", 0, "select count(*) from device_registrations");
        assertCount("chat conversations", 180, "select count(*) from chat_conversations");
        assertCount("chat messages", 2400, "select count(*) from chat_messages");
        assertCount("chat read states", 360, "select count(*) from chat_read_state");
        assertCount("notifications", 1200, "select count(*) from notifications");
        assertCount("covered notification types", 23, "select count(distinct type) from notifications");
        assertCount("non-historical push statuses", 0, """
                select count(*) from notifications where push_status <> 'NOT_REQUESTED'
                """);
        assertCount("messages sent by outsiders", 0, """
                select count(*)
                from chat_messages message
                join chat_conversations conversation on conversation.id = message.conversation_id
                where message.sender_id not in (conversation.guide_id, conversation.tourist_id)
                """);
        assertCount("inaccessible chat notifications", 0, """
                select count(*)
                from notifications notification
                left join chat_conversations conversation
                    on conversation.id = (notification.payload ->> 'chatId')::uuid
                where notification.type = 'CHAT_MESSAGE'
                  and (
                      conversation.id is null
                      or notification.recipient_id not in (
                          conversation.guide_id,
                          conversation.tourist_id
                      )
                  )
                """);
        assertCount("notifications with missing reservation references", 0, """
                select count(*)
                from notifications notification
                left join reservations reservation
                    on reservation.id = (notification.payload ->> 'reservationId')::uuid
                where jsonb_exists(notification.payload, 'reservationId')
                  and reservation.id is null
                """);
        assertCount("notifications with missing payment references", 0, """
                select count(*)
                from notifications notification
                left join payments payment
                    on payment.id = (notification.payload ->> 'paymentId')::uuid
                where jsonb_exists(notification.payload, 'paymentId')
                  and payment.id is null
                """);
        assertCount("notifications with missing review references", 0, """
                select count(*)
                from notifications notification
                left join reviews review
                    on review.id = (notification.payload ->> 'reviewId')::uuid
                where notification.type in ('RATING_RECEIVED', 'COMMENT_RECEIVED')
                  and review.id is null
                """);
        assertCount("high-volume tourists without a second notification page", 0, """
                select count(*)
                from generate_series(1231, 1250) user_id
                where (
                    select count(*) from notifications
                    where recipient_id = user_id
                ) < 10
                """);
        assertCount("high-volume guides without a second notification page", 0, """
                select count(*)
                from generate_series(2046, 2050) user_id
                where (
                    select count(*) from notifications
                    where recipient_id = user_id
                ) < 20
                """);
    }

    private void verifyDerivedInvariants(Instant referenceInstant) {
        assertCount("oversubscribed sessions", 0, """
                select count(*)
                from tour_sessions session
                join (
                    select reservation.session_id, sum(reservation.participant_count) occupied
                    from reservations reservation
                    where reservation.status in ('CONFIRMED', 'COMPLETED')
                       or (reservation.status = 'PENDING_PAYMENT'
                           and reservation.hold_expires_at
                               > ?)
                    group by reservation.session_id
                ) occupancy on occupancy.session_id = session.id
                where occupancy.occupied > session.capacity
                """, Timestamp.from(referenceInstant));
        assertGroupedCounts(
                "computed guide levels",
                """
                with completed_sessions as (
                    select tour.guide_id, count(*) as completed_count
                    from tour_sessions session
                    join tours tour on tour.id = session.tour_id
                    where session.status = 'COMPLETED'
                    group by tour.guide_id
                ), ratings as (
                    select tour.guide_id, avg(review.rating) as average_rating, count(*) as review_count
                    from reviews review
                    join reservations reservation on reservation.id = review.reservation_id
                    join tour_sessions session on session.id = reservation.session_id
                    join tours tour on tour.id = session.tour_id
                    group by tour.guide_id
                ), levels as (
                    select guide.id,
                           case
                               when coalesce(session.completed_count, 0) >= 100
                                and coalesce(rating.average_rating, 0) >= 4.8
                                and coalesce(rating.review_count, 0) >= 30 then 'LEGENDARY'
                               when coalesce(session.completed_count, 0) >= 20
                                and coalesce(rating.average_rating, 0) >= 4.5
                                and coalesce(rating.review_count, 0) >= 10 then 'SUPER'
                               when coalesce(session.completed_count, 0) >= 5
                                and coalesce(rating.average_rating, 0) >= 3.7
                                and coalesce(rating.review_count, 0) >= 3 then 'SILVER'
                               else 'APPROVED'
                           end as level
                    from users guide
                    left join completed_sessions session on session.guide_id = guide.id
                    left join ratings rating on rating.guide_id = guide.id
                    where guide.id between 2001 and 2050
                )
                select level, count(*) from levels group by level
                """,
                Map.of("APPROVED", 35L, "SILVER", 10L, "SUPER", 4L, "LEGENDARY", 1L)
        );
    }

    private void assertGroupedCounts(String label, String sql, Map<String, Long> expected) {
        Map<String, Long> actual = jdbcTemplate.query(sql, (resultSet, rowNumber) -> Map.entry(
                        resultSet.getString(1),
                        resultSet.getLong(2)
                )).stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        if (!actual.equals(expected)) {
            throw new IllegalStateException(label + " are inconsistent: " + actual);
        }
    }

    private void assertCount(String label, long expected, String sql, Object... arguments) {
        long actual = count(sql, arguments);
        if (actual != expected) {
            throw new IllegalStateException(
                    label + " are inconsistent: expected " + expected + ", actual " + actual
            );
        }
    }

    private long count(String sql, Object... arguments) {
        Long value = jdbcTemplate.queryForObject(sql, Long.class, arguments);
        if (value == null) {
            throw new IllegalStateException("Demo verification query returned no result");
        }
        return value;
    }
}
