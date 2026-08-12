package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.domain.CheckoutLocale;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.BuyerProfileProvider;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedCheckoutCommand;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedCheckoutSession;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedPaymentGateway;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.PaymentGatewayException;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PaymentCheckoutService {

    private final PaymentIntentService paymentIntentService;
    private final HostedPaymentGateway paymentGateway;
    private final BuyerProfileProvider buyerProfileProvider;
    private final SavedPaymentMethodStateService savedPaymentMethodStateService;
    private final ProviderFailureCodeMapper failureCodeMapper;

    public Payment checkoutTour(
            User tourist,
            UUID sessionId,
            int participantCount,
            PaymentMethod method,
            UUID quoteId,
            CheckoutLocale locale,
            String idempotencyKey
    ) {
        if (method == PaymentMethod.WALLET) {
            if (quoteId != null) {
                throw new BusinessException(ErrorCode.MALFORMED_REQUEST);
            }
            return paymentIntentService.purchaseTourWithWallet(
                    tourist,
                    sessionId,
                    participantCount,
                    idempotencyKey
            );
        }
        requireHostedCheckoutInputs(quoteId, locale);
        HostedPaymentIntent intent = paymentIntentService.createHostedTourIntent(
                tourist,
                sessionId,
                participantCount,
                quoteId,
                idempotencyKey
        );
        return initialize(intent, tourist, locale, "GuideMate tour booking");
    }

    public Payment checkoutWalletTopUp(
            User tourist,
            UUID quoteId,
            CheckoutLocale locale,
            String idempotencyKey
    ) {
        requireHostedCheckoutInputs(quoteId, locale);
        HostedPaymentIntent intent = paymentIntentService.createTopUpIntent(
                tourist,
                quoteId,
                idempotencyKey
        );
        return initialize(intent, tourist, locale, "GuideMate wallet top-up");
    }

    private Payment initialize(
            HostedPaymentIntent intent,
            User user,
            CheckoutLocale locale,
            String itemName
    ) {
        Payment payment = intent.payment();
        if (!intent.initializationRequired() || payment.getStatus() != PaymentStatus.PENDING) {
            return payment;
        }
        String conversationId = "guidemate-" + payment.getId();
        try {
            HostedCheckoutSession session = paymentGateway.initialize(new HostedCheckoutCommand(
                    payment.getId(),
                    conversationId,
                    payment.getChargeAmountMinor(),
                    payment.getChargeCurrencyCode(),
                    locale,
                    itemName,
                    buyerProfileProvider.get(user),
                    savedPaymentMethodStateService.findProviderCustomerKey(user.getId())
            ));
            return paymentIntentService.completeInitialization(payment.getId(), session, conversationId);
        } catch (PaymentGatewayException exception) {
            String stableCode = failureCodeMapper.toStableCode(exception.providerFailureCode());
            paymentIntentService.failInitialization(payment.getId(), stableCode);
            throw new BusinessException(ErrorCode.PAYMENT_INITIALIZATION_FAILED);
        } catch (IllegalStateException exception) {
            paymentIntentService.failInitialization(payment.getId(), ErrorCode.PAYMENT_INITIALIZATION_FAILED.name());
            throw new BusinessException(ErrorCode.PAYMENT_INITIALIZATION_FAILED);
        }
    }

    private void requireHostedCheckoutInputs(UUID quoteId, CheckoutLocale locale) {
        if (quoteId == null) {
            throw new BusinessException(ErrorCode.FX_QUOTE_EXPIRED);
        }
        if (locale == null) {
            throw new BusinessException(ErrorCode.MALFORMED_REQUEST);
        }
    }
}
