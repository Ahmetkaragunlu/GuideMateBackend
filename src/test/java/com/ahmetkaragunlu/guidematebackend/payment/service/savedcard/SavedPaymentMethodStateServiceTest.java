package com.ahmetkaragunlu.guidematebackend.payment.service.savedcard;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.provider.PaymentProviderCustomer;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.savedcard.ProviderCardDetails;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentProviderCustomerRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.SavedPaymentMethodRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SavedPaymentMethodStateServiceTest {

    @Mock private PaymentProviderCustomerRepository customerRepository;
    @Mock private SavedPaymentMethodRepository methodRepository;
    @Mock private UserRepository userRepository;
    @Mock private SensitiveDataCipher dataCipher;
    @Mock private User user;
    private SavedPaymentMethodStateService service;

    @BeforeEach
    void setUp() {
        service = new SavedPaymentMethodStateService(
                customerRepository,
                methodRepository,
                userRepository,
                dataCipher
        );
    }

    @Test
    void capturesNewProviderCardUsingEncryptedSecretsAndFingerprint() {
        when(user.getId()).thenReturn(42L);
        when(userRepository.findByIdForUpdate(42L)).thenReturn(Optional.of(user));
        when(dataCipher.fingerprint("customer-key")).thenReturn("customer-fingerprint");
        when(dataCipher.encrypt("customer-key")).thenReturn("encrypted-customer");
        when(dataCipher.fingerprint("card-token")).thenReturn("card-fingerprint");
        when(dataCipher.encrypt("card-token")).thenReturn("encrypted-card");
        when(methodRepository.findByUserIdForUpdate(42L)).thenReturn(new ArrayList<>());

        service.capture(42L, card("customer-key", "card-token", "0006"));

        verify(customerRepository).saveAndFlush(any(PaymentProviderCustomer.class));
        verify(methodRepository).save(org.mockito.ArgumentMatchers.argThat(method ->
                "encrypted-card".equals(method.getProviderCardTokenEncrypted())
                        && "card-fingerprint".equals(method.getProviderCardTokenFingerprint())
                        && "0006".equals(method.getLastFourDigits())));
        verify(methodRepository).flush();
    }

    @Test
    void rejectsMalformedProviderCardWithoutPersistingIt() {
        when(user.getId()).thenReturn(42L);
        when(userRepository.findByIdForUpdate(42L)).thenReturn(Optional.of(user));
        when(dataCipher.fingerprint("customer-key")).thenReturn("customer-fingerprint");
        when(dataCipher.encrypt("customer-key")).thenReturn("encrypted-customer");
        when(dataCipher.fingerprint("card-token")).thenReturn("card-fingerprint");
        when(methodRepository.findByUserIdForUpdate(42L)).thenReturn(new ArrayList<>());

        assertThatThrownBy(() -> service.capture(42L, card("customer-key", "card-token", "12AB")))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.SAVED_CARD_SYNC_FAILED));
        verify(methodRepository, never()).save(any());
    }

    private ProviderCardDetails card(String customerKey, String token, String lastFourDigits) {
        return new ProviderCardDetails(
                customerKey,
                token,
                "Kişisel kart",
                "Test Bank",
                "1",
                "Bonus",
                "MASTER_CARD",
                "CREDIT_CARD",
                lastFourDigits,
                "Test User",
                12,
                2030
        );
    }
}
