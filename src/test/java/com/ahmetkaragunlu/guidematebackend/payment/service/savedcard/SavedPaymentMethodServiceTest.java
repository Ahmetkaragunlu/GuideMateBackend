package com.ahmetkaragunlu.guidematebackend.payment.service.savedcard;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.provider.PaymentGatewayException;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.savedcard.SavedCardGateway;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SavedPaymentMethodServiceTest {

    @Mock private SavedPaymentMethodStateService stateService;
    @Mock private SavedCardGateway gateway;
    @Mock private User user;
    private SavedPaymentMethodService service;

    @BeforeEach
    void setUp() {
        service = new SavedPaymentMethodService(stateService, gateway);
    }

    @Test
    void returnsEmptyWithoutProviderCustomer() {
        when(user.getId()).thenReturn(42L);
        assertThat(service.getCards(user)).isEmpty();
        verify(gateway, never()).list(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void mapsProviderFailureToStableBusinessError() {
        when(user.getId()).thenReturn(42L);
        when(stateService.findProviderCustomerKey(42L)).thenReturn("customer-key");
        when(gateway.list("customer-key")).thenThrow(new PaymentGatewayException("NETWORK"));

        assertThatThrownBy(() -> service.getCards(user))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.SAVED_CARD_PROVIDER_UNAVAILABLE));
    }

    @Test
    void deletesProviderCardBeforeMarkingLocalRecordDeleted() {
        UUID methodId = UUID.randomUUID();
        when(user.getId()).thenReturn(42L);
        when(stateService.prepareDeletion(42L, methodId))
                .thenReturn(new SavedCardDeletion(methodId, "customer-key", "card-token"));

        service.deleteCard(user, methodId);

        verify(gateway).delete("customer-key", "card-token");
        verify(stateService).markDeleted(42L, methodId);
    }
}
