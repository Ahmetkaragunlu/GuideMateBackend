package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.VerifiedPaymentResult;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentEventRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationFinalizationResult;
import com.ahmetkaragunlu.guidematebackend.tour.domain.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.service.GuideEarningService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.WalletAccountService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class PaymentResultServiceTest {

    @Mock
    private PaymentRepository paymentRepository;
    @Mock
    private PaymentEventRepository paymentEventRepository;
    @Mock
    private ReservationBookingService reservationBookingService;
    @Mock
    private PaymentRefundService refundService;
    @Mock
    private WalletAccountService walletAccountService;
    @Mock
    private GuideEarningService guideEarningService;
    @Mock
    private ProviderFailureCodeMapper failureCodeMapper;
    @Mock
    private SensitiveDataCipher dataCipher;
    @Mock
    private NotificationPublisher notificationPublisher;

    private PaymentResultService service;

    @BeforeEach
    void setUp() {
        service = new PaymentResultService(
                paymentRepository,
                paymentEventRepository,
                reservationBookingService,
                refundService,
                walletAccountService,
                guideEarningService,
                failureCodeMapper,
                dataCipher,
                notificationPublisher,
                Clock.fixed(Instant.parse("2026-08-13T00:00:00Z"), ZoneOffset.UTC)
        );
    }

    @Test
    void lateVerifiedTourPaymentFinalizesWhenCapacityRemains() {
        LateTourPayment fixture = stubLateTourPayment(false);

        service.apply(
                fixture.paymentId(),
                successfulProviderResult(),
                new ProviderVerifiedEvent("RECONCILIATION", "reconciliation:event", "payload-hash")
        );

        verify(reservationBookingService).finalizeAfterPaymentVerification(fixture.reservationId());
        verify(guideEarningService).createPending(fixture.reservation());
        verify(reservationBookingService, never()).expire(fixture.reservationId());
        verify(refundService, never()).requestFullRefund(any(), any(), any());
    }

    @Test
    void lateVerifiedTourPaymentRequestsOneRefundWhenCapacityIsGone() {
        LateTourPayment fixture = stubLateTourPayment(true);

        service.apply(
                fixture.paymentId(),
                successfulProviderResult(),
                new ProviderVerifiedEvent("RECONCILIATION", "reconciliation:event", "payload-hash")
        );

        verify(refundService).requestFullRefund(
                fixture.paymentId(),
                fixture.user(),
                "late-payment:" + fixture.paymentId()
        );
        verify(guideEarningService, never()).createPending(any());
    }

    @Test
    void rejectsSuccessfulProviderResultWithDifferentChargeAmount() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = org.mockito.Mockito.mock(Payment.class);

        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getReservation()).thenReturn(null);
        when(payment.getProviderTokenEncrypted()).thenReturn("encrypted-token");
        when(payment.getProviderConversationId()).thenReturn("conversation-id");
        when(payment.getChargeAmountMinor()).thenReturn(9_000L);
        when(dataCipher.decrypt("encrypted-token")).thenReturn("checkout-token");

        assertThatThrownBy(() -> service.apply(
                paymentId,
                new VerifiedPaymentResult(
                        true,
                        "checkout-token",
                        "conversation-id",
                        "provider-payment-id",
                        "provider-transaction-id",
                        9_001L,
                        "EUR",
                        "SUCCESS",
                        null,
                        null
                ),
                new ProviderVerifiedEvent("CALLBACK", "callback:event", "payload-hash")
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_VERIFICATION_FAILED));

        verify(payment, never()).succeed(any(), any(), any());
    }

    @Test
    void ignoresAlreadyRecordedProviderEventWithoutApplyingMoneyMovementAgain() {
        UUID paymentId = UUID.randomUUID();
        Payment payment = org.mockito.Mockito.mock(Payment.class);

        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(payment.getReservation()).thenReturn(null);
        when(payment.getProviderTokenEncrypted()).thenReturn("encrypted-token");
        when(payment.getProviderConversationId()).thenReturn("conversation-id");
        when(payment.getChargeAmountMinor()).thenReturn(10_000L);
        when(payment.getChargeCurrencyCode()).thenReturn("USD");
        when(dataCipher.decrypt("encrypted-token")).thenReturn("checkout-token");
        when(paymentEventRepository.existsByProviderEventId("webhook:event")).thenReturn(true);

        Payment result = service.apply(
                paymentId,
                new VerifiedPaymentResult(
                        true,
                        "checkout-token",
                        "conversation-id",
                        "provider-payment-id",
                        "provider-transaction-id",
                        10_000L,
                        "USD",
                        "SUCCESS",
                        null,
                        null
                ),
                new ProviderVerifiedEvent("WEBHOOK", "webhook:event", "payload-hash")
        );

        assertThat(result).isSameAs(payment);
        verify(payment, never()).succeed(any(), any(), any());
        verify(paymentEventRepository, never()).save(any());
        verify(walletAccountService, never()).credit(any(), any(Long.class), any(), any(), any(), any(), any());
    }

    private LateTourPayment stubLateTourPayment(boolean refundRequired) {
        UUID paymentId = UUID.randomUUID();
        UUID reservationId = UUID.randomUUID();
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        Reservation reservation = org.mockito.Mockito.mock(Reservation.class);
        TourSession session = org.mockito.Mockito.mock(TourSession.class);
        Tour tour = org.mockito.Mockito.mock(Tour.class);
        User user = org.mockito.Mockito.mock(User.class);

        when(paymentRepository.findById(paymentId)).thenReturn(Optional.of(payment));
        when(paymentRepository.findByIdForUpdate(paymentId)).thenReturn(Optional.of(payment));
        when(paymentEventRepository.existsByProviderEventId("reconciliation:event")).thenReturn(false);
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getReservation()).thenReturn(reservation);
        when(payment.getStatus()).thenReturn(PaymentStatus.TIMEOUT);
        when(payment.getPurpose()).thenReturn(PaymentPurpose.TOUR_BOOKING);
        when(payment.getProviderTokenEncrypted()).thenReturn("encrypted-token");
        when(payment.getProviderConversationId()).thenReturn("conversation-id");
        when(payment.getAmountMinor()).thenReturn(10_000L);
        when(payment.getCurrencyCode()).thenReturn("USD");
        when(payment.getChargeAmountMinor()).thenReturn(10_000L);
        when(payment.getChargeCurrencyCode()).thenReturn("USD");
        when(payment.getUser()).thenReturn(user);
        when(user.getId()).thenReturn(42L);
        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getSession()).thenReturn(session);
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(UUID.randomUUID());
        when(dataCipher.decrypt("encrypted-token")).thenReturn("checkout-token");
        when(reservationBookingService.finalizeAfterPaymentVerification(reservationId))
                .thenReturn(new ReservationFinalizationResult(reservation, refundRequired));
        return new LateTourPayment(paymentId, reservationId, reservation, user);
    }

    private VerifiedPaymentResult successfulProviderResult() {
        return new VerifiedPaymentResult(
                true,
                "checkout-token",
                "conversation-id",
                "provider-payment-id",
                "provider-transaction-id",
                10_000L,
                "USD",
                "SUCCESS",
                null,
                null
        );
    }

    private record LateTourPayment(
            UUID paymentId,
            UUID reservationId,
            Reservation reservation,
            User user
    ) {
    }
}
