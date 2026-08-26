package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import com.iyzipay.Options;
import com.iyzipay.model.Card;
import com.iyzipay.model.CardList;
import com.iyzipay.model.Locale;
import com.iyzipay.request.DeleteCardRequest;
import com.iyzipay.request.RetrieveCardListRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class IyzicoSavedCardGateway implements SavedCardGateway {

    private static final String SUCCESS = "success";

    private final Options options;

    @Override
    public List<ProviderCardDetails> list(String customerKey) {
        RetrieveCardListRequest request = new RetrieveCardListRequest();
        request.setLocale(Locale.EN.getValue());
        request.setConversationId("guidemate-card-list-" + UUID.randomUUID());
        request.setCardUserKey(customerKey);

        return IyzicoGatewaySupport.execute(() -> {
            CardList response = CardList.retrieve(request, options);
            if (!SUCCESS.equalsIgnoreCase(response.getStatus())
                    || !customerKey.equals(response.getCardUserKey())) {
                throw new PaymentGatewayException(IyzicoGatewaySupport.normalizeFailureCode(response.getErrorCode()));
            }
            if (response.getCardDetails() == null) {
                return List.of();
            }
            return response.getCardDetails().stream()
                    .map(card -> toProviderCard(response.getCardUserKey(), card))
                    .toList();
        });
    }

    @Override
    public void delete(String customerKey, String cardToken) {
        DeleteCardRequest request = new DeleteCardRequest();
        request.setLocale(Locale.EN.getValue());
        request.setConversationId("guidemate-card-delete-" + UUID.randomUUID());
        request.setCardUserKey(customerKey);
        request.setCardToken(cardToken);

        IyzicoGatewaySupport.execute(() -> {
            Card response = Card.delete(request, options);
            if (!SUCCESS.equalsIgnoreCase(response.getStatus())) {
                throw new PaymentGatewayException(IyzicoGatewaySupport.normalizeFailureCode(response.getErrorCode()));
            }
        });
    }

    private ProviderCardDetails toProviderCard(String customerKey, Card card) {
        return new ProviderCardDetails(
                customerKey,
                card.getCardToken(),
                card.getCardAlias(),
                card.getCardBankName(),
                card.getCardBankCode() == null ? null : card.getCardBankCode().toString(),
                card.getCardFamily(),
                card.getCardAssociation(),
                card.getCardType(),
                card.getLastFourDigits(),
                card.getCardHolderName(),
                parseInteger(card.getExpireMonth()),
                parseInteger(card.getExpireYear())
        );
    }

    private Integer parseInteger(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Integer.valueOf(value);
        } catch (NumberFormatException exception) {
            throw new PaymentGatewayException("PROVIDER_RESPONSE_INVALID");
        }
    }
}
