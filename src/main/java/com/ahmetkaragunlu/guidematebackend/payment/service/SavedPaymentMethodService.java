package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.domain.SavedPaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.dto.SavedPaymentMethodResponse;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.PaymentGatewayException;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ProviderCardDetails;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.SavedCardGateway;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SavedPaymentMethodService {

    private final SavedPaymentMethodStateService stateService;
    private final SavedCardGateway savedCardGateway;

    public List<SavedPaymentMethodResponse> getCards(User user) {
        String customerKey = stateService.findProviderCustomerKey(user.getId());
        if (customerKey == null) {
            return List.of();
        }
        List<ProviderCardDetails> providerCards;
        try {
            providerCards = savedCardGateway.list(customerKey);
        } catch (PaymentGatewayException exception) {
            throw new BusinessException(ErrorCode.SAVED_CARD_PROVIDER_UNAVAILABLE);
        }
        return stateService.synchronize(user.getId(), customerKey, providerCards).stream()
                .map(this::toResponse)
                .toList();
    }

    public void deleteCard(User user, UUID methodId) {
        SavedCardDeletion deletion = stateService.prepareDeletion(user.getId(), methodId);
        if (deletion == null) {
            return;
        }
        try {
            savedCardGateway.delete(deletion.customerKey(), deletion.cardToken());
        } catch (PaymentGatewayException exception) {
            throw new BusinessException(ErrorCode.SAVED_CARD_PROVIDER_UNAVAILABLE);
        }
        stateService.markDeleted(user.getId(), methodId);
    }

    public SavedPaymentMethodResponse makeDefault(User user, UUID methodId) {
        return toResponse(stateService.makeDefault(user.getId(), methodId));
    }

    private SavedPaymentMethodResponse toResponse(SavedPaymentMethod method) {
        return new SavedPaymentMethodResponse(
                method.getId(),
                method.getAlias(),
                method.getBankName(),
                method.getBankCode(),
                method.getCardFamily(),
                method.getCardAssociation(),
                method.getCardType(),
                method.getLastFourDigits(),
                method.getCardHolderName(),
                method.getExpiryMonth() == null ? null : method.getExpiryMonth().intValue(),
                method.getExpiryYear() == null ? null : method.getExpiryYear().intValue(),
                method.isDefaultMethod()
        );
    }
}
