package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.iyzipay.Options;
import com.iyzipay.model.Address;
import com.iyzipay.model.BasketItem;
import com.iyzipay.model.BasketItemType;
import com.iyzipay.model.Buyer;
import com.iyzipay.model.CheckoutForm;
import com.iyzipay.model.CheckoutFormInitialize;
import com.iyzipay.model.Locale;
import com.iyzipay.model.PaymentGroup;
import com.iyzipay.model.PaymentItem;
import com.iyzipay.model.Refund;
import com.iyzipay.model.RefundReason;
import com.iyzipay.request.CreateCheckoutFormInitializeRequest;
import com.iyzipay.request.CreateRefundRequest;
import com.iyzipay.request.RetrieveCheckoutFormRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.Duration;
import java.util.List;

@Component
@RequiredArgsConstructor
public class IyzicoPaymentGateway implements HostedPaymentGateway {

    private static final String SUCCESS = "success";
    private static final String PAYMENT_SUCCESS = "SUCCESS";
    private static final String CALLBACK_PATH = "/api/v1/payments/iyzico/callback";

    private final Options options;
    private final PaymentProperties properties;

    @Override
    public HostedCheckoutSession initialize(HostedCheckoutCommand command) {
        CreateCheckoutFormInitializeRequest request = new CreateCheckoutFormInitializeRequest();
        request.setLocale(command.locale().providerValue());
        request.setConversationId(command.conversationId());
        request.setPrice(toMajor(command.amountMinor()));
        request.setPaidPrice(toMajor(command.amountMinor()));
        request.setCurrency(command.currencyCode());
        request.setBasketId(command.paymentId().toString());
        request.setPaymentGroup(PaymentGroup.PRODUCT.name());
        request.setCallbackUrl(properties.callbackUri(CALLBACK_PATH).toString());
        request.setBuyer(toBuyer(command.buyer()));
        request.setBillingAddress(toAddress(command.buyer()));
        request.setBasketItems(List.of(toBasketItem(command)));
        if (!isBlank(command.providerCustomerKey())) {
            request.setCardUserKey(command.providerCustomerKey());
            request.setPaymentWithNewCardEnabled(true);
        }

        try {
            CheckoutFormInitialize response = CheckoutFormInitialize.create(request, options);
            if (!SUCCESS.equalsIgnoreCase(response.getStatus())
                    || !response.verifySignature(options.getSecretKey())
                    || isBlank(response.getToken())
                    || isBlank(response.getPaymentPageUrl())) {
                throw new PaymentGatewayException(normalizeFailureCode(response.getErrorCode()));
            }
            Duration expiresIn = response.getTokenExpireTime() == null
                    ? properties.checkoutExpiration()
                    : Duration.ofSeconds(response.getTokenExpireTime());
            if (expiresIn.isZero() || expiresIn.isNegative()) {
                expiresIn = properties.checkoutExpiration();
            }
            return new HostedCheckoutSession(response.getToken(), response.getPaymentPageUrl(), expiresIn);
        } catch (PaymentGatewayException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new PaymentGatewayException("PROVIDER_UNAVAILABLE");
        }
    }

    @Override
    public VerifiedPaymentResult retrieve(String token, String conversationId) {
        RetrieveCheckoutFormRequest request = new RetrieveCheckoutFormRequest();
        request.setLocale(Locale.EN.getValue());
        request.setConversationId(conversationId);
        request.setToken(token);

        try {
            CheckoutForm response = CheckoutForm.retrieve(request, options);
            if (!SUCCESS.equalsIgnoreCase(response.getStatus())
                    || !response.verifySignature(options.getSecretKey())) {
                throw new PaymentGatewayException(normalizeFailureCode(response.getErrorCode()));
            }
            boolean successful = PAYMENT_SUCCESS.equalsIgnoreCase(response.getPaymentStatus());
            PaymentItem item = response.getPaymentItems() == null || response.getPaymentItems().isEmpty()
                    ? null
                    : response.getPaymentItems().get(0);
            return new VerifiedPaymentResult(
                    successful,
                    response.getToken(),
                    response.getConversationId(),
                    response.getPaymentId(),
                    item == null ? null : item.getPaymentTransactionId(),
                    toMinor(response.getPaidPrice()),
                    response.getCurrency(),
                    response.getPaymentStatus(),
                    successful ? null : normalizeFailureCode(response.getErrorCode()),
                    successful ? toProviderCard(response) : null
            );
        } catch (PaymentGatewayException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new PaymentGatewayException("PROVIDER_UNAVAILABLE");
        }
    }

    @Override
    public ProviderRefundResult refund(ProviderRefundCommand command) {
        CreateRefundRequest request = new CreateRefundRequest();
        request.setLocale(Locale.EN.getValue());
        request.setConversationId(command.conversationId());
        request.setPaymentTransactionId(command.providerTransactionId());
        request.setPrice(toMajor(command.amountMinor()));
        request.setCurrency(command.currencyCode());
        request.setIp(command.ipAddress());
        request.setReason(RefundReason.BUYER_REQUEST);
        request.setDescription("GuideMate reservation refund");

        try {
            Refund response = Refund.create(request, options);
            if (!SUCCESS.equalsIgnoreCase(response.getStatus())
                    || !response.verifySignature(options.getSecretKey())) {
                return new ProviderRefundResult(false, null, normalizeFailureCode(response.getErrorCode()));
            }
            String providerRefundId = firstNonBlank(
                    response.getRefundHostReference(),
                    response.getHostReference(),
                    response.getConversationId()
            );
            return new ProviderRefundResult(true, providerRefundId, null);
        } catch (PaymentGatewayException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new PaymentGatewayException("PROVIDER_UNAVAILABLE");
        }
    }

    private Buyer toBuyer(BuyerProfile profile) {
        Buyer buyer = new Buyer();
        buyer.setId(profile.id());
        buyer.setName(profile.firstName());
        buyer.setSurname(profile.lastName());
        buyer.setEmail(profile.email());
        buyer.setIdentityNumber(profile.identityNumber());
        buyer.setGsmNumber(profile.phoneNumber());
        buyer.setRegistrationAddress(profile.address());
        buyer.setCity(profile.city());
        buyer.setCountry(profile.country());
        buyer.setZipCode(profile.zipCode());
        buyer.setIp(profile.ipAddress());
        return buyer;
    }

    private Address toAddress(BuyerProfile profile) {
        Address address = new Address();
        address.setContactName(profile.firstName() + " " + profile.lastName());
        address.setAddress(profile.address());
        address.setCity(profile.city());
        address.setCountry(profile.country());
        address.setZipCode(profile.zipCode());
        return address;
    }

    private BasketItem toBasketItem(HostedCheckoutCommand command) {
        BasketItem item = new BasketItem();
        item.setId(command.paymentId().toString());
        item.setName(command.itemName());
        item.setCategory1("Tourism");
        item.setItemType(BasketItemType.VIRTUAL.name());
        item.setPrice(toMajor(command.amountMinor()));
        return item;
    }

    private ProviderCardDetails toProviderCard(CheckoutForm response) {
        if (isBlank(response.getCardUserKey())) {
            return null;
        }
        return new ProviderCardDetails(
                response.getCardUserKey(),
                response.getCardToken(),
                null,
                response.getBankName(),
                null,
                response.getCardFamily(),
                response.getCardAssociation(),
                response.getCardType(),
                response.getLastFourDigits(),
                null,
                null,
                null
        );
    }

    private BigDecimal toMajor(long amountMinor) {
        return BigDecimal.valueOf(amountMinor, 2);
    }

    private long toMinor(BigDecimal amount) {
        if (amount == null) {
            return 0;
        }
        return amount.movePointRight(2).longValueExact();
    }

    private String normalizeFailureCode(String value) {
        return isBlank(value) ? "PROVIDER_REJECTED" : value.trim();
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (!isBlank(value)) {
                return value;
            }
        }
        return null;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
