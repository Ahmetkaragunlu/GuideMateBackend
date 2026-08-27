package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.CheckoutLocale;
import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.BuyerProfile;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.BuyerProfileProvider;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedCheckoutCommand;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedCheckoutSession;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.HostedPaymentGateway;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.PaymentGatewayException;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PaymentCheckoutServiceTest {

    @Mock
    private PaymentIntentService paymentIntentService;
    @Mock
    private HostedPaymentGateway paymentGateway;
    @Mock
    private BuyerProfileProvider buyerProfileProvider;
    @Mock
    private SavedPaymentMethodStateService savedPaymentMethodStateService;
    @Mock
    private ProviderFailureCodeMapper failureCodeMapper;

    private PaymentCheckoutService service;

    @BeforeEach
    void setUp() {
        service = new PaymentCheckoutService(
                paymentIntentService,
                paymentGateway,
                buyerProfileProvider,
                savedPaymentMethodStateService,
                failureCodeMapper
        );
    }

    @Test
    void delegatesWalletPurchaseWithoutHostedCheckout() {
        User tourist = org.mockito.Mockito.mock(User.class);
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        UUID sessionId = UUID.randomUUID();
        when(paymentIntentService.purchaseTourWithWallet(tourist, sessionId, 2, "wallet-key"))
                .thenReturn(payment);

        Payment result = service.checkoutTour(
                tourist,
                sessionId,
                2,
                PaymentMethod.WALLET,
                null,
                null,
                "wallet-key"
        );

        assertThat(result).isSameAs(payment);
        verify(paymentGateway, never()).initialize(any());
    }

    @Test
    void rejectsQuoteForWalletPurchase() {
        assertThatThrownBy(() -> service.checkoutTour(
                org.mockito.Mockito.mock(User.class),
                UUID.randomUUID(),
                1,
                PaymentMethod.WALLET,
                UUID.randomUUID(),
                null,
                "wallet-key"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.MALFORMED_REQUEST));

        verify(paymentIntentService, never()).purchaseTourWithWallet(any(), any(), any(Integer.class), any());
    }

    @Test
    void initializesHostedTourCheckoutWithCanonicalPaymentData() {
        User tourist = org.mockito.Mockito.mock(User.class);
        Payment pending = pendingPayment();
        Payment initialized = org.mockito.Mockito.mock(Payment.class);
        UUID sessionId = UUID.randomUUID();
        UUID quoteId = UUID.randomUUID();
        BuyerProfile buyer = buyerProfile();
        HostedCheckoutSession checkoutSession = new HostedCheckoutSession(
                "provider-token",
                "https://sandbox.example/checkout",
                Duration.ofMinutes(30)
        );
        when(paymentIntentService.createHostedTourIntent(
                tourist,
                sessionId,
                2,
                quoteId,
                "hosted-key"
        )).thenReturn(new HostedPaymentIntent(pending, true));
        when(buyerProfileProvider.get(tourist)).thenReturn(buyer);
        when(savedPaymentMethodStateService.findProviderCustomerKey(tourist.getId()))
                .thenReturn("customer-key");
        when(paymentGateway.initialize(any(HostedCheckoutCommand.class))).thenReturn(checkoutSession);
        when(paymentIntentService.completeInitialization(
                pending.getId(),
                checkoutSession,
                "guidemate-" + pending.getId()
        )).thenReturn(initialized);

        Payment result = service.checkoutTour(
                tourist,
                sessionId,
                2,
                PaymentMethod.HOSTED_CARD,
                quoteId,
                CheckoutLocale.EN,
                "hosted-key"
        );

        assertThat(result).isSameAs(initialized);
        ArgumentCaptor<HostedCheckoutCommand> commandCaptor =
                ArgumentCaptor.forClass(HostedCheckoutCommand.class);
        verify(paymentGateway).initialize(commandCaptor.capture());
        assertThat(commandCaptor.getValue())
                .satisfies(command -> {
                    assertThat(command.paymentId()).isEqualTo(pending.getId());
                    assertThat(command.amountMinor()).isEqualTo(47_758L);
                    assertThat(command.currencyCode()).isEqualTo("TRY");
                    assertThat(command.locale()).isEqualTo(CheckoutLocale.EN);
                    assertThat(command.providerCustomerKey()).isEqualTo("customer-key");
                });
    }

    @Test
    void doesNotInitializeProviderAgainForCompletedIdempotentIntent() {
        User tourist = org.mockito.Mockito.mock(User.class);
        Payment previous = org.mockito.Mockito.mock(Payment.class);
        UUID quoteId = UUID.randomUUID();
        when(paymentIntentService.createTopUpIntent(tourist, quoteId, "retry-key"))
                .thenReturn(new HostedPaymentIntent(previous, false));

        Payment result = service.checkoutWalletTopUp(
                tourist,
                quoteId,
                CheckoutLocale.TR,
                "retry-key"
        );

        assertThat(result).isSameAs(previous);
        verify(paymentGateway, never()).initialize(any());
        verify(paymentIntentService, never()).completeInitialization(any(), any(), any());
    }

    @Test
    void marksInitializationFailedWithStableProviderCode() {
        User tourist = org.mockito.Mockito.mock(User.class);
        Payment pending = pendingPayment();
        UUID quoteId = UUID.randomUUID();
        when(paymentIntentService.createTopUpIntent(tourist, quoteId, "failure-key"))
                .thenReturn(new HostedPaymentIntent(pending, true));
        when(buyerProfileProvider.get(tourist)).thenReturn(buyerProfile());
        when(paymentGateway.initialize(any()))
                .thenThrow(new PaymentGatewayException("provider-declined"));
        when(failureCodeMapper.toStableCode("provider-declined")).thenReturn("CARD_DECLINED");

        assertThatThrownBy(() -> service.checkoutWalletTopUp(
                tourist,
                quoteId,
                CheckoutLocale.EN,
                "failure-key"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.PAYMENT_INITIALIZATION_FAILED));

        verify(paymentIntentService).failInitialization(pending.getId(), "CARD_DECLINED");
        verify(paymentIntentService, never()).completeInitialization(any(), any(), any());
    }

    @Test
    void requiresQuoteAndLocaleForHostedCheckout() {
        User tourist = org.mockito.Mockito.mock(User.class);

        assertThatThrownBy(() -> service.checkoutWalletTopUp(
                tourist,
                null,
                CheckoutLocale.EN,
                "missing-quote"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.FX_QUOTE_EXPIRED));
        assertThatThrownBy(() -> service.checkoutWalletTopUp(
                tourist,
                UUID.randomUUID(),
                null,
                "missing-locale"
        )).isInstanceOfSatisfying(BusinessException.class, exception ->
                assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.MALFORMED_REQUEST));

        verify(paymentIntentService, never()).createTopUpIntent(any(), any(), any());
    }

    private Payment pendingPayment() {
        Payment payment = org.mockito.Mockito.mock(Payment.class);
        when(payment.getId()).thenReturn(UUID.randomUUID());
        when(payment.getStatus()).thenReturn(PaymentStatus.PENDING);
        when(payment.getChargeAmountMinor()).thenReturn(47_758L);
        when(payment.getChargeCurrencyCode()).thenReturn("TRY");
        return payment;
    }

    private BuyerProfile buyerProfile() {
        return new BuyerProfile(
                "42",
                "Test",
                "Tourist",
                "tourist@example.com",
                "11111111111",
                "+905551112233",
                "Test address",
                "Istanbul",
                "Turkey",
                "34000",
                "127.0.0.1"
        );
    }
}
