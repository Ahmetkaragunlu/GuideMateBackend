package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.PurchaseSnapshot;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.PurchaseSnapshotCodec;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WalletLedgerEntry;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.WalletTransactionResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.mapper.WalletMapper;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class WalletTransactionQueryServiceTest {

    @Mock
    private WalletAccountService walletAccountService;
    @Mock
    private PaymentRepository paymentRepository;
    @Mock
    private RefundRepository refundRepository;
    @Mock
    private GuideEarningRepository guideEarningRepository;
    @Mock
    private PurchaseSnapshotCodec snapshotCodec;
    @Mock
    private WalletMapper walletMapper;

    private WalletTransactionQueryService service;

    @BeforeEach
    void setUp() {
        service = new WalletTransactionQueryService(
                walletAccountService,
                paymentRepository,
                refundRepository,
                guideEarningRepository,
                snapshotCodec,
                walletMapper
        );
    }

    @Test
    void resolvesTourTitlesInBatchesAndLeavesGeneralTransactionsUntitled() {
        User user = mock(User.class);
        UUID paymentId = UUID.randomUUID();
        UUID refundId = UUID.randomUUID();
        UUID earningId = UUID.randomUUID();
        WalletLedgerEntry purchaseEntry = entry(LedgerEntryType.TOUR_PURCHASE, paymentId);
        WalletLedgerEntry refundEntry = entry(LedgerEntryType.REFUND, refundId);
        WalletLedgerEntry earningEntry = entry(LedgerEntryType.GUIDE_EARNING, earningId);
        WalletLedgerEntry reversalEntry = entry(LedgerEntryType.EARNING_REVERSAL, earningId);
        WalletLedgerEntry topUpEntry = entry(LedgerEntryType.TOP_UP, UUID.randomUUID());
        WalletLedgerEntry withdrawalEntry = entry(LedgerEntryType.WITHDRAWAL, UUID.randomUUID());
        List<WalletLedgerEntry> entries = List.of(
                purchaseEntry,
                refundEntry,
                earningEntry,
                reversalEntry,
                topUpEntry,
                withdrawalEntry
        );

        Reservation purchaseReservation = reservation("purchase-snapshot", "Purchased tour");
        Reservation refundReservation = reservation("refund-snapshot", "Refunded tour");
        Reservation earningReservation = reservation("earning-snapshot", "Guided tour");
        Payment payment = mock(Payment.class);
        Payment refundPayment = mock(Payment.class);
        Refund refund = mock(Refund.class);
        GuideEarning earning = mock(GuideEarning.class);

        when(walletAccountService.getTransactions(user, 0, 20))
                .thenReturn(new PageImpl<>(entries, PageRequest.of(0, 20), entries.size()));
        when(payment.getId()).thenReturn(paymentId);
        when(payment.getReservation()).thenReturn(purchaseReservation);
        when(paymentRepository.findAllByIdIn(java.util.Set.of(paymentId))).thenReturn(List.of(payment));
        when(refund.getId()).thenReturn(refundId);
        when(refund.getPayment()).thenReturn(refundPayment);
        when(refundPayment.getReservation()).thenReturn(refundReservation);
        when(refundRepository.findAllByIdIn(java.util.Set.of(refundId))).thenReturn(List.of(refund));
        when(earning.getId()).thenReturn(earningId);
        when(earning.getReservation()).thenReturn(earningReservation);
        when(guideEarningRepository.findAllByIdIn(java.util.Set.of(earningId))).thenReturn(List.of(earning));
        entries.forEach(entry -> when(walletMapper.toTransaction(
                org.mockito.ArgumentMatchers.eq(entry),
                nullable(String.class)
        )).thenReturn(mock(WalletTransactionResponse.class)));

        service.getTransactions(user, 0, 20);

        verify(paymentRepository).findAllByIdIn(java.util.Set.of(paymentId));
        verify(refundRepository).findAllByIdIn(java.util.Set.of(refundId));
        verify(guideEarningRepository).findAllByIdIn(java.util.Set.of(earningId));
        verify(walletMapper).toTransaction(purchaseEntry, "Purchased tour");
        verify(walletMapper).toTransaction(refundEntry, "Refunded tour");
        verify(walletMapper).toTransaction(earningEntry, "Guided tour");
        verify(walletMapper).toTransaction(reversalEntry, "Guided tour");
        verify(walletMapper).toTransaction(topUpEntry, null);
        verify(walletMapper).toTransaction(withdrawalEntry, null);
    }

    @Test
    void skipsReferenceRepositoriesForGeneralTransactions() {
        User user = mock(User.class);
        WalletLedgerEntry topUpEntry = entry(LedgerEntryType.TOP_UP, UUID.randomUUID());
        when(walletAccountService.getTransactions(user, 0, 20))
                .thenReturn(new PageImpl<>(List.of(topUpEntry), PageRequest.of(0, 20), 1));
        when(walletMapper.toTransaction(topUpEntry, null)).thenReturn(mock(WalletTransactionResponse.class));

        service.getTransactions(user, 0, 20);

        verifyNoInteractions(paymentRepository, refundRepository, guideEarningRepository, snapshotCodec);
    }

    private WalletLedgerEntry entry(LedgerEntryType type, UUID referenceId) {
        WalletLedgerEntry entry = mock(WalletLedgerEntry.class);
        when(entry.getId()).thenReturn(UUID.randomUUID());
        when(entry.getType()).thenReturn(type);
        if (type != LedgerEntryType.TOP_UP && type != LedgerEntryType.WITHDRAWAL) {
            when(entry.getReferenceId()).thenReturn(referenceId);
        }
        return entry;
    }

    private Reservation reservation(String encodedSnapshot, String title) {
        Reservation reservation = mock(Reservation.class);
        PurchaseSnapshot snapshot = mock(PurchaseSnapshot.class);
        when(reservation.getPurchaseSnapshot()).thenReturn(encodedSnapshot);
        when(snapshotCodec.decode(encodedSnapshot)).thenReturn(snapshot);
        when(snapshot.title()).thenReturn(title);
        return reservation;
    }
}
