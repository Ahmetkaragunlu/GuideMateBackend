package com.ahmetkaragunlu.guidematebackend.payment.service.payment;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.checkout.PaymentFxQuote;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.payment.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.refund.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.domain.refund.RefundStatus;
import com.ahmetkaragunlu.guidematebackend.payment.dto.response.PaymentResponse;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.ReservationStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentQueryServiceTest {

    @Mock
    private PaymentRepository paymentRepository;
    @Mock
    private RefundRepository refundRepository;
    @Mock
    private User currentUser;

    private PaymentQueryService service;

    @BeforeEach
    void setUp() {
        service = new PaymentQueryService(paymentRepository, refundRepository);
    }

    @Test
    void rejectsPaymentThatIsNotOwnedByCurrentUser() {
        UUID paymentId = UUID.randomUUID();
        when(currentUser.getId()).thenReturn(42L);
        when(paymentRepository.findOwnedDetails(paymentId, 42L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.getOwned(currentUser, paymentId))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_NOT_FOUND)
                );
    }

    @Test
    void mapsCanonicalPaymentReservationAndLatestRefundDetails() {
        UUID paymentId = UUID.randomUUID();
        UUID quoteId = UUID.randomUUID();
        UUID reservationId = UUID.randomUUID();
        UUID refundId = UUID.randomUUID();
        Instant quotedAt = Instant.parse("2026-09-24T10:00:00Z");
        Instant expiresAt = Instant.parse("2026-09-24T10:30:00Z");
        Instant createdAt = Instant.parse("2026-09-24T09:59:00Z");
        Instant updatedAt = Instant.parse("2026-09-24T10:01:00Z");
        Payment payment = payment(
                paymentId,
                PaymentStatus.REQUIRES_ACTION,
                "https://checkout.iyzico.test/token",
                quoteId,
                reservationId,
                quotedAt,
                expiresAt,
                createdAt,
                updatedAt
        );
        Refund refund = org.mockito.Mockito.mock(Refund.class);
        when(refund.getId()).thenReturn(refundId);
        when(refund.getStatus()).thenReturn(RefundStatus.PROCESSING);
        when(refund.getAmountMinor()).thenReturn(4_000L);
        when(refund.getChargeAmountMinor()).thenReturn(4_150L);
        when(refund.getChargeCurrencyCode()).thenReturn("EUR");
        when(currentUser.getId()).thenReturn(42L);
        when(paymentRepository.findOwnedDetails(paymentId, 42L)).thenReturn(Optional.of(payment));
        when(refundRepository.findFirstByPayment_IdOrderByCreatedAtDesc(paymentId))
                .thenReturn(Optional.of(refund));

        PaymentResponse response = service.getOwned(currentUser, paymentId);

        assertThat(response).usingRecursiveComparison().isEqualTo(new PaymentResponse(
                paymentId,
                PaymentPurpose.TOUR_BOOKING,
                PaymentMethod.HOSTED_CARD,
                PaymentStatus.REQUIRES_ACTION,
                10_000L,
                "USD",
                quoteId,
                10_375L,
                "EUR",
                new BigDecimal("1.037500000000"),
                "ECB",
                quotedAt,
                "https://checkout.iyzico.test/token",
                expiresAt,
                reservationId,
                ReservationStatus.PENDING_PAYMENT,
                refundId,
                RefundStatus.PROCESSING,
                4_000L,
                4_150L,
                "EUR",
                "provider-timeout",
                createdAt,
                updatedAt
        ));
    }

    @Test
    void hidesStoredPaymentPageUrlAfterPaymentLeavesRequiresActionState() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = payment(
                paymentId,
                PaymentStatus.SUCCEEDED,
                "https://checkout.iyzico.test/stale-token",
                null,
                null,
                null,
                null,
                Instant.parse("2026-09-24T09:59:00Z"),
                Instant.parse("2026-09-24T10:01:00Z")
        );
        when(currentUser.getId()).thenReturn(42L);
        when(paymentRepository.findOwnedDetails(paymentId, 42L)).thenReturn(Optional.of(payment));
        when(refundRepository.findFirstByPayment_IdOrderByCreatedAtDesc(paymentId))
                .thenReturn(Optional.empty());

        PaymentResponse response = service.getOwned(currentUser, paymentId);

        assertThat(response.paymentPageUrl()).isNull();
    }

    private Payment payment(
            UUID paymentId,
            PaymentStatus status,
            String paymentPageUrl,
            UUID quoteId,
            UUID reservationId,
            Instant quotedAt,
            Instant expiresAt,
            Instant createdAt,
            Instant updatedAt
    ) {
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getPurpose()).thenReturn(PaymentPurpose.TOUR_BOOKING);
        when(payment.getMethod()).thenReturn(PaymentMethod.HOSTED_CARD);
        when(payment.getStatus()).thenReturn(status);
        when(payment.getAmountMinor()).thenReturn(10_000L);
        when(payment.getCurrencyCode()).thenReturn("USD");
        when(payment.getChargeAmountMinor()).thenReturn(10_375L);
        when(payment.getChargeCurrencyCode()).thenReturn("EUR");
        when(payment.getFxRate()).thenReturn(new BigDecimal("1.037500000000"));
        when(payment.getFxRateSource()).thenReturn("ECB");
        when(payment.getFxQuotedAt()).thenReturn(quotedAt);
        if (status == PaymentStatus.REQUIRES_ACTION) {
            when(payment.getPaymentPageUrl()).thenReturn(paymentPageUrl);
        }
        when(payment.getExpiresAt()).thenReturn(expiresAt);
        when(payment.getFailureCode()).thenReturn("provider-timeout");
        when(payment.getCreatedAt()).thenReturn(createdAt);
        when(payment.getUpdatedAt()).thenReturn(updatedAt);
        if (quoteId == null) {
            when(payment.getFxQuote()).thenReturn(null);
        } else {
            PaymentFxQuote quote = org.mockito.Mockito.mock(PaymentFxQuote.class);
            when(quote.getId()).thenReturn(quoteId);
            when(payment.getFxQuote()).thenReturn(quote);
        }
        if (reservationId == null) {
            when(payment.getReservation()).thenReturn(null);
        } else {
            Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
            when(reservation.getId()).thenReturn(reservationId);
            when(reservation.getStatus()).thenReturn(ReservationStatus.PENDING_PAYMENT);
            when(payment.getReservation()).thenReturn(reservation);
        }
        return payment;
    }
}
