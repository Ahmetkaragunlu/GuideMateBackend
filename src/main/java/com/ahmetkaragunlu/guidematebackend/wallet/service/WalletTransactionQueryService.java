package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Refund;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.RefundRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.PurchaseSnapshotCodec;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.GuideEarning;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.WalletLedgerEntry;
import com.ahmetkaragunlu.guidematebackend.wallet.dto.WalletTransactionResponse;
import com.ahmetkaragunlu.guidematebackend.wallet.mapper.WalletMapper;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.GuideEarningRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class WalletTransactionQueryService {

    private static final Set<LedgerEntryType> EARNING_TYPES = EnumSet.of(
            LedgerEntryType.GUIDE_EARNING,
            LedgerEntryType.EARNING_REVERSAL
    );

    private final WalletAccountService walletAccountService;
    private final PaymentRepository paymentRepository;
    private final RefundRepository refundRepository;
    private final GuideEarningRepository guideEarningRepository;
    private final PurchaseSnapshotCodec snapshotCodec;
    private final WalletMapper walletMapper;

    @Transactional(readOnly = true)
    public PageResponse<WalletTransactionResponse> getTransactions(User user, int page, int size) {
        Page<WalletLedgerEntry> entries = walletAccountService.getTransactions(user, page, size);
        Map<UUID, String> titles = resolveTitles(entries.getContent());
        return PageResponse.from(entries.map(entry -> walletMapper.toTransaction(
                entry,
                titles.get(entry.getId())
        )));
    }

    private Map<UUID, String> resolveTitles(Collection<WalletLedgerEntry> entries) {
        Map<UUID, String> titles = new HashMap<>();
        mapPaymentTitles(entries, titles);
        mapRefundTitles(entries, titles);
        mapEarningTitles(entries, titles);
        return titles;
    }

    private void mapPaymentTitles(Collection<WalletLedgerEntry> entries, Map<UUID, String> titles) {
        Set<UUID> referenceIds = referenceIds(entries, Set.of(LedgerEntryType.TOUR_PURCHASE));
        if (referenceIds.isEmpty()) {
            return;
        }
        Map<UUID, String> titleByReference = paymentRepository.findAllByIdIn(referenceIds).stream()
                .filter(payment -> payment.getReservation() != null)
                .collect(Collectors.toMap(Payment::getId, payment -> title(payment.getReservation())));
        mapEntryTitles(entries, LedgerEntryType.TOUR_PURCHASE, titleByReference, titles);
    }

    private void mapRefundTitles(Collection<WalletLedgerEntry> entries, Map<UUID, String> titles) {
        Set<UUID> referenceIds = referenceIds(entries, Set.of(LedgerEntryType.REFUND));
        if (referenceIds.isEmpty()) {
            return;
        }
        Map<UUID, String> titleByReference = refundRepository.findAllByIdIn(referenceIds).stream()
                .filter(refund -> refund.getPayment().getReservation() != null)
                .collect(Collectors.toMap(
                        Refund::getId,
                        refund -> title(refund.getPayment().getReservation())
                ));
        mapEntryTitles(entries, LedgerEntryType.REFUND, titleByReference, titles);
    }

    private void mapEarningTitles(Collection<WalletLedgerEntry> entries, Map<UUID, String> titles) {
        Set<UUID> referenceIds = referenceIds(entries, EARNING_TYPES);
        if (referenceIds.isEmpty()) {
            return;
        }
        Map<UUID, String> titleByReference = guideEarningRepository.findAllByIdIn(referenceIds).stream()
                .collect(Collectors.toMap(
                        GuideEarning::getId,
                        earning -> title(earning.getReservation())
                ));
        entries.stream()
                .filter(entry -> EARNING_TYPES.contains(entry.getType()))
                .forEach(entry -> putTitle(entry, titleByReference, titles));
    }

    private Set<UUID> referenceIds(Collection<WalletLedgerEntry> entries, Set<LedgerEntryType> types) {
        return entries.stream()
                .filter(entry -> types.contains(entry.getType()))
                .map(WalletLedgerEntry::getReferenceId)
                .collect(Collectors.toSet());
    }

    private void mapEntryTitles(
            Collection<WalletLedgerEntry> entries,
            LedgerEntryType type,
            Map<UUID, String> titleByReference,
            Map<UUID, String> titles
    ) {
        entries.stream()
                .filter(entry -> entry.getType() == type)
                .forEach(entry -> putTitle(entry, titleByReference, titles));
    }

    private void putTitle(
            WalletLedgerEntry entry,
            Map<UUID, String> titleByReference,
            Map<UUID, String> titles
    ) {
        String title = titleByReference.get(entry.getReferenceId());
        if (title != null) {
            titles.put(entry.getId(), title);
        }
    }

    private String title(Reservation reservation) {
        return snapshotCodec.decode(reservation.getPurchaseSnapshot()).title();
    }
}
