package com.ahmetkaragunlu.guidematebackend.wallet.service.earning;

import com.ahmetkaragunlu.guidematebackend.notification.service.NotificationPublisher;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.tour.domain.tour.Tour;
import com.ahmetkaragunlu.guidematebackend.tour.domain.session.TourSession;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.earning.GuideEarningStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletEntryCommand;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuideEarningLifecycleServiceTest {

    private static final Instant NOW = Instant.parse("2026-08-14T00:00:00Z");

    @Mock
    private GuideEarningRepository earningRepository;
    @Mock
    private WalletAccountService walletAccountService;
    @Mock
    private PaymentProperties paymentProperties;
    @Mock
    private NotificationPublisher notificationPublisher;

    private GuideEarningLifecycleService service;

    @BeforeEach
    void setUp() {
        service = new GuideEarningLifecycleService(
                earningRepository,
                walletAccountService,
                paymentProperties,
                notificationPublisher,
                Clock.fixed(NOW, ZoneOffset.UTC)
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

    @Test
    void makesDuePendingEarningAvailableAndCreditsWalletOnlyOnce() {
        UUID earningId = UUID.randomUUID();
        UUID reservationId = UUID.randomUUID();
        UUID tourId = UUID.randomUUID();
        GuideEarning earning = mock(GuideEarning.class);
        Reservation reservation = mock(Reservation.class);
        TourSession session = mock(TourSession.class);
        Tour tour = mock(Tour.class);
        User guide = mock(User.class);
        Wallet wallet = mock(Wallet.class);
        when(earningRepository.findByIdForUpdate(earningId))
                .thenReturn(Optional.of(earning));
        when(earning.getStatus())
                .thenReturn(GuideEarningStatus.PENDING, GuideEarningStatus.AVAILABLE);
        when(earning.getAvailableAt()).thenReturn(NOW);
        when(earning.getReservation()).thenReturn(reservation);
        when(earning.getId()).thenReturn(earningId);
        when(earning.getNetMinor()).thenReturn(8_500L);
        when(earning.getCurrencyCode()).thenReturn("USD");
        when(reservation.getId()).thenReturn(reservationId);
        when(reservation.getSession()).thenReturn(session);
        when(session.getTour()).thenReturn(tour);
        when(tour.getId()).thenReturn(tourId);
        when(tour.getGuide()).thenReturn(guide);
        when(guide.getId()).thenReturn(7L);
        when(walletAccountService.getOrCreateForUpdate(guide)).thenReturn(wallet);

        service.makeAvailableById(earningId);
        service.makeAvailableById(earningId);

        verify(earning).makeAvailable();
        verify(walletAccountService).credit(
                wallet,
                new WalletEntryCommand(
                        8_500L,
                        LedgerEntryType.GUIDE_EARNING,
                        "GUIDE_EARNING",
                        earningId,
                        "earning-credit:" + earningId,
                        NOW
                )
        );
        verify(notificationPublisher).publish(any());
        verify(earningRepository, times(2)).findByIdForUpdate(earningId);
    }

}
