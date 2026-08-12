package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentFxQuote;
import com.ahmetkaragunlu.guidematebackend.payment.dto.CheckoutCurrenciesResponse;
import com.ahmetkaragunlu.guidematebackend.payment.dto.CheckoutCurrencyOptionResponse;
import com.ahmetkaragunlu.guidematebackend.payment.dto.PaymentQuoteResponse;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ExchangeRate;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ExchangeRateProvider;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ExchangeRateUnavailableException;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationBookingService;
import com.ahmetkaragunlu.guidematebackend.reservation.service.ReservationPurchasePreview;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Clock;
import java.time.LocalDate;
import java.util.Currency;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentQuoteService {

    private static final String IDENTITY_RATE_SOURCE = "IDENTITY_USD";
    private static final int STORED_RATE_SCALE = 12;

    private final ReservationBookingService reservationBookingService;
    private final PaymentQuoteStateService stateService;
    private final ExchangeRateProvider exchangeRateProvider;
    private final PaymentProperties properties;
    private final Clock clock;

    public CheckoutCurrenciesResponse getCurrencyOptions() {
        List<CheckoutCurrencyOptionResponse> options = properties.fx().enabledChargeCurrencies().stream()
                .sorted()
                .map(code -> new CheckoutCurrencyOptionResponse(code, fractionDigits(code)))
                .toList();
        return new CheckoutCurrenciesResponse(properties.canonicalCurrencyCode(), options);
    }

    public PaymentQuoteResponse quoteTour(
            User user,
            UUID sessionId,
            int participantCount,
            String chargeCurrencyCode
    ) {
        ReservationPurchasePreview preview = reservationBookingService.previewPurchase(
                user,
                sessionId,
                participantCount
        );
        FxCalculation calculation = calculate(preview.totalPriceMinor(), chargeCurrencyCode);
        return toResponse(stateService.saveTourQuote(user, preview, calculation));
    }

    public PaymentQuoteResponse quoteWalletTopUp(User user, long amountMinor, String chargeCurrencyCode) {
        requireTourist(user);
        if (amountMinor <= 0) {
            throw new BusinessException(ErrorCode.INVALID_AMOUNT);
        }
        FxCalculation calculation = calculate(amountMinor, chargeCurrencyCode);
        return toResponse(stateService.saveWalletTopUpQuote(user, amountMinor, calculation));
    }

    private FxCalculation calculate(long baseAmountMinor, String requestedCurrencyCode) {
        String chargeCurrencyCode = normalizeSupportedCurrency(requestedCurrencyCode);
        ExchangeRate exchangeRate;
        if (properties.canonicalCurrencyCode().equals(chargeCurrencyCode)) {
            exchangeRate = new ExchangeRate(
                    properties.canonicalCurrencyCode(),
                    chargeCurrencyCode,
                    BigDecimal.ONE,
                    IDENTITY_RATE_SOURCE,
                    LocalDate.now(clock)
            );
        } else {
            try {
                exchangeRate = exchangeRateProvider.latest(
                        properties.canonicalCurrencyCode(),
                        chargeCurrencyCode
                );
            } catch (ExchangeRateUnavailableException exception) {
                throw new BusinessException(ErrorCode.FX_QUOTE_UNAVAILABLE, exception);
            }
        }

        try {
            int baseFractionDigits = fractionDigits(properties.canonicalCurrencyCode());
            int chargeFractionDigits = fractionDigits(chargeCurrencyCode);
            BigDecimal chargeMajor = BigDecimal.valueOf(baseAmountMinor, baseFractionDigits)
                    .multiply(exchangeRate.rate())
                    .setScale(chargeFractionDigits, RoundingMode.HALF_UP);
            long chargeAmountMinor = chargeMajor.movePointRight(chargeFractionDigits).longValueExact();
            if (chargeAmountMinor <= 0) {
                throw new ArithmeticException("Converted amount is not positive");
            }
            return new FxCalculation(
                    chargeAmountMinor,
                    chargeCurrencyCode,
                    exchangeRate.rate().setScale(STORED_RATE_SCALE, RoundingMode.HALF_UP),
                    exchangeRate.source(),
                    exchangeRate.rateDate()
            );
        } catch (ArithmeticException exception) {
            throw new BusinessException(ErrorCode.FX_QUOTE_UNAVAILABLE, exception);
        }
    }

    private String normalizeSupportedCurrency(String value) {
        String currencyCode = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!properties.fx().enabledChargeCurrencies().contains(currencyCode)) {
            throw new BusinessException(ErrorCode.PAYMENT_CURRENCY_NOT_SUPPORTED);
        }
        return currencyCode;
    }

    private int fractionDigits(String currencyCode) {
        try {
            int fractionDigits = Currency.getInstance(currencyCode).getDefaultFractionDigits();
            if (fractionDigits < 0) {
                throw new IllegalArgumentException("Currency has no fraction digits");
            }
            return fractionDigits;
        } catch (IllegalArgumentException exception) {
            throw new BusinessException(ErrorCode.PAYMENT_CURRENCY_NOT_SUPPORTED, exception);
        }
    }

    private PaymentQuoteResponse toResponse(PaymentFxQuote quote) {
        return new PaymentQuoteResponse(
                quote.getId(),
                quote.getPurpose(),
                quote.getBaseAmountMinor(),
                quote.getBaseCurrencyCode(),
                quote.getChargeAmountMinor(),
                quote.getChargeCurrencyCode(),
                quote.getFxRate(),
                quote.getRateSource(),
                quote.getRateDate(),
                quote.getQuotedAt(),
                quote.getExpiresAt()
        );
    }

    private void requireTourist(User user) {
        if (user.getRole() == null || !RoleType.ROLE_TOURIST.name().equals(user.getRole().getName())) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
    }
}
