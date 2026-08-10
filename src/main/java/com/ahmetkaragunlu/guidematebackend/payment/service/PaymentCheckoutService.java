package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
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
    private final ProviderFailureCodeMapper failureCodeMapper;

    public Payment checkoutTour(
            User tourist,
            UUID sessionId,
            int participantCount,
            PaymentMethod method,
            String idempotencyKey
    ) {
        if (method == PaymentMethod.WALLET) {
            return paymentIntentService.purchaseTourWithWallet(
                    tourist,
                    sessionId,
                    participantCount,
                    idempotencyKey
            );
        }
        HostedPaymentIntent intent = paymentIntentService.createHostedTourIntent(
                tourist,
                sessionId,
                participantCount,
                idempotencyKey
        );
        return initialize(intent, tourist, "GuideMate tour booking");
    }

    public Payment checkoutWalletTopUp(User tourist, long amountMinor, String idempotencyKey) {
        HostedPaymentIntent intent = paymentIntentService.createTopUpIntent(
                tourist,
                amountMinor,
                idempotencyKey
        );
        return initialize(intent, tourist, "GuideMate wallet top-up");
    }

    private Payment initialize(HostedPaymentIntent intent, User user, String itemName) {
        Payment payment = intent.payment();
        if (!intent.initializationRequired() || payment.getStatus() != PaymentStatus.PENDING) {
            return payment;
        }
        String conversationId = "guidemate-" + payment.getId();
        try {
            HostedCheckoutSession session = paymentGateway.initialize(new HostedCheckoutCommand(
                    payment.getId(),
                    conversationId,
                    payment.getAmountMinor(),
                    payment.getCurrencyCode(),
                    itemName,
                    buyerProfileProvider.get(user)
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
}
