package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentFxQuote;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentPurpose;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentFxQuoteRepository;
import com.ahmetkaragunlu.guidematebackend.reservation.domain.Reservation;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationPurchasePreview;
import com.ahmetkaragunlu.guidematebackend.tour.repository.TourSessionRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentQuoteStateService {

    private final PaymentFxQuoteRepository quoteRepository;
    private final UserRepository userRepository;
    private final TourSessionRepository tourSessionRepository;
    private final PaymentProperties properties;
    private final Clock clock;

    @Transactional
    public PaymentFxQuote saveTourQuote(
            User user,
            ReservationPurchasePreview preview,
            FxCalculation calculation
    ) {
        Instant quotedAt = clock.instant();
        return quoteRepository.save(PaymentFxQuote.tour(
                userRepository.getReferenceById(user.getId()),
                tourSessionRepository.getReferenceById(preview.sessionId()),
                preview.participantCount(),
                preview.totalPriceMinor(),
                preview.currencyCode(),
                calculation.chargeAmountMinor(),
                calculation.chargeCurrencyCode(),
                calculation.rate(),
                calculation.rateSource(),
                calculation.rateDate(),
                quotedAt,
                quotedAt.plus(properties.fx().quoteTtl())
        ));
    }

    @Transactional
    public PaymentFxQuote saveWalletTopUpQuote(
            User user,
            long amountMinor,
            FxCalculation calculation
    ) {
        Instant quotedAt = clock.instant();
        return quoteRepository.save(PaymentFxQuote.walletTopUp(
                userRepository.getReferenceById(user.getId()),
                amountMinor,
                properties.canonicalCurrencyCode(),
                calculation.chargeAmountMinor(),
                calculation.chargeCurrencyCode(),
                calculation.rate(),
                calculation.rateSource(),
                calculation.rateDate(),
                quotedAt,
                quotedAt.plus(properties.fx().quoteTtl())
        ));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public PaymentFxQuote requireTourQuote(User user, UUID quoteId, Reservation reservation) {
        PaymentFxQuote quote = requireOwnedActiveQuote(user, quoteId, PaymentPurpose.TOUR_BOOKING);
        boolean matches = quote.getSession() != null
                && quote.getSession().getId().equals(reservation.getSession().getId())
                && quote.getParticipantCount() != null
                && quote.getParticipantCount() == reservation.getParticipantCount()
                && quote.getBaseAmountMinor() == reservation.getTotalPriceMinor()
                && quote.getBaseCurrencyCode().equals(reservation.getCurrencyCode());
        if (!matches) {
            throw new BusinessException(ErrorCode.FX_QUOTE_EXPIRED);
        }
        return quote;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public PaymentFxQuote requireWalletTopUpQuote(User user, UUID quoteId) {
        return requireOwnedActiveQuote(user, quoteId, PaymentPurpose.WALLET_TOP_UP);
    }

    private PaymentFxQuote requireOwnedActiveQuote(User user, UUID quoteId, PaymentPurpose purpose) {
        if (quoteId == null) {
            throw new BusinessException(ErrorCode.FX_QUOTE_EXPIRED);
        }
        PaymentFxQuote quote = quoteRepository.findByIdForUpdate(quoteId)
                .orElseThrow(() -> new BusinessException(ErrorCode.FX_QUOTE_EXPIRED));
        if (!quote.getUser().getId().equals(user.getId())
                || quote.getPurpose() != purpose
                || quote.isExpired(clock.instant())) {
            throw new BusinessException(ErrorCode.FX_QUOTE_EXPIRED);
        }
        if (!properties.fx().enabledChargeCurrencies().contains(quote.getChargeCurrencyCode())) {
            throw new BusinessException(ErrorCode.PAYMENT_CURRENCY_NOT_SUPPORTED);
        }
        return quote;
    }
}
