package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.tour.domain.TourSession;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.SessionEarningSummary;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuideEarningServiceTest {

    @Mock
    private GuideEarningRepository earningRepository;
    @Mock
    private WalletAccountService walletAccountService;
    @Mock
    private PaymentProperties paymentProperties;
    @Mock
    private NotificationPublisher notificationPublisher;

    private GuideEarningService service;

    @BeforeEach
    void setUp() {
        service = new GuideEarningService(
                earningRepository,
                walletAccountService,
                paymentProperties,
                notificationPublisher,
                Clock.fixed(Instant.parse("2026-08-14T00:00:00Z"), ZoneOffset.UTC)
        );
    }

    @Test
    void sessionNetEarningsIncludePendingAndAvailableButNotReversed() {
        UUID sessionId = UUID.randomUUID();
        SessionEarningSummary summary = org.mockito.Mockito.mock(SessionEarningSummary.class);
        when(summary.getSessionId()).thenReturn(sessionId);
        when(summary.getNetEarningsMinor()).thenReturn(8_500L);
        when(earningRepository.summarizeBySessionIdsAndStatuses(eq(List.of(sessionId)), any()))
                .thenReturn(List.of(summary));

        Map<UUID, Long> earnings = service.sessionNetEarnings(List.of(sessionId));

        assertThat(earnings).containsEntry(sessionId, 8_500L);
        verify(earningRepository).summarizeBySessionIdsAndStatuses(
                List.of(sessionId),
                List.of(GuideEarningStatus.PENDING, GuideEarningStatus.AVAILABLE)
        );
    }

    @Test
    void createsPendingEarningWithConfiguredCommission() {
        UUID reservationId = UUID.randomUUID();
        Reservation reservation = mock(Reservation.class);
        TourSession session = mock(TourSession.class);
        Instant availableAt = Instant.parse("2026-08-15T12:00:00Z");
        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getTotalPriceMinor()).thenReturn(10_000L);
        when(reservation.getCurrencyCode()).thenReturn("USD");
        when(reservation.getSession()).thenReturn(session);
        when(session.endsAt()).thenReturn(availableAt);
        when(paymentProperties.platformCommissionBasisPoints()).thenReturn(1_500);
        when(earningRepository.findByReservation_Id(reservationId)).thenReturn(Optional.empty());
        when(earningRepository.save(any(GuideEarning.class))).thenAnswer(invocation -> invocation.getArgument(0));

        GuideEarning earning = service.createPending(reservation);

        assertThat(earning.getGrossMinor()).isEqualTo(10_000L);
        assertThat(earning.getPlatformFeeMinor()).isEqualTo(1_500L);
        assertThat(earning.getNetMinor()).isEqualTo(8_500L);
        assertThat(earning.getCurrencyCode()).isEqualTo("USD");
        assertThat(earning.getAvailableAt()).isEqualTo(availableAt);
        assertThat(earning.getStatus()).isEqualTo(GuideEarningStatus.PENDING);
    }

    @Test
    void returnsExistingEarningWithoutCreatingDuplicate() {
        UUID reservationId = UUID.randomUUID();
        Reservation reservation = mock(Reservation.class);
        GuideEarning existing = mock(GuideEarning.class);
        when(reservation.getId()).thenReturn(reservationId);
        when(earningRepository.findByReservation_Id(reservationId)).thenReturn(Optional.of(existing));

        assertThat(service.createPending(reservation)).isSameAs(existing);
        verify(earningRepository, never()).save(any());
    }

}
