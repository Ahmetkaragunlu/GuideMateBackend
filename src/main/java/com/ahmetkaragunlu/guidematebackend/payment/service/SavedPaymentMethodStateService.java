package com.ahmetkaragunlu.guidematebackend.payment.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentProviderCustomer;
import com.ahmetkaragunlu.guidematebackend.payment.domain.SavedCardMetadata;
import com.ahmetkaragunlu.guidematebackend.payment.domain.SavedPaymentMethod;
import com.ahmetkaragunlu.guidematebackend.payment.domain.SavedPaymentMethodStatus;
import com.ahmetkaragunlu.guidematebackend.payment.gateway.ProviderCardDetails;
import com.ahmetkaragunlu.guidematebackend.payment.repository.PaymentProviderCustomerRepository;
import com.ahmetkaragunlu.guidematebackend.payment.repository.SavedPaymentMethodRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SavedPaymentMethodStateService {

    private static final int MAX_PROVIDER_KEY_LENGTH = 1024;
    private static final int MAX_ALIAS_LENGTH = 100;
    private static final int MAX_BANK_NAME_LENGTH = 128;
    private static final int MAX_BANK_CODE_LENGTH = 16;
    private static final int MAX_CARD_FAMILY_LENGTH = 64;
    private static final int MAX_CARD_CLASSIFICATION_LENGTH = 32;
    private static final int MAX_CARD_HOLDER_LENGTH = 160;

    private final PaymentProviderCustomerRepository customerRepository;
    private final SavedPaymentMethodRepository methodRepository;
    private final UserRepository userRepository;
    private final SensitiveDataCipher dataCipher;

    @Transactional(readOnly = true)
    public String findProviderCustomerKey(Long userId) {
        return customerRepository.findById(userId)
                .map(this::decryptCustomerKey)
                .orElse(null);
    }

    @Transactional
    public void capture(Long userId, ProviderCardDetails providerCard) {
        if (providerCard == null || isBlank(providerCard.customerKey())) {
            return;
        }
        String customerKey = requireProviderValue(providerCard.customerKey());
        User user = lockUser(userId);
        requireOrCreateCustomer(user, customerKey);
        if (isBlank(providerCard.cardToken())) {
            return;
        }

        List<SavedPaymentMethod> methods = methodRepository.findByUserIdForUpdate(userId);
        upsert(user, methods, providerCard);
        normalizeDefault(methods);
        methodRepository.flush();
    }

    @Transactional
    public List<SavedPaymentMethod> synchronize(
            Long userId,
            String expectedCustomerKey,
            List<ProviderCardDetails> providerCards
    ) {
        User user = lockUser(userId);
        requireMatchingCustomer(userId, expectedCustomerKey);
        List<SavedPaymentMethod> methods = new ArrayList<>(methodRepository.findByUserIdForUpdate(userId));
        Set<String> providerFingerprints = new HashSet<>();

        for (ProviderCardDetails providerCard : providerCards) {
            if (!expectedCustomerKey.equals(providerCard.customerKey())) {
                throw syncFailed();
            }
            SavedPaymentMethod method = upsert(user, methods, providerCard);
            providerFingerprints.add(method.getProviderCardTokenFingerprint());
        }
        methods.stream()
                .filter(method -> method.getStatus() == SavedPaymentMethodStatus.ACTIVE)
                .filter(method -> !providerFingerprints.contains(method.getProviderCardTokenFingerprint()))
                .forEach(SavedPaymentMethod::markDeleted);

        normalizeDefault(methods);
        methodRepository.flush();
        return methodRepository.findByUser_IdAndStatusOrderByDefaultMethodDescCreatedAtAsc(
                userId,
                SavedPaymentMethodStatus.ACTIVE
        );
    }

    @Transactional
    public SavedCardDeletion prepareDeletion(Long userId, UUID methodId) {
        lockUser(userId);
        String customerKey = requireCustomerKey(userId);
        SavedPaymentMethod method = methodRepository.findOwnedByIdForUpdate(methodId, userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.SAVED_CARD_NOT_FOUND));
        if (method.getStatus() == SavedPaymentMethodStatus.DELETED) {
            return null;
        }
        if (method.getStatus() != SavedPaymentMethodStatus.ACTIVE) {
            throw new BusinessException(ErrorCode.SAVED_CARD_NOT_FOUND);
        }
        return new SavedCardDeletion(
                methodId,
                customerKey,
                decryptCardToken(method)
        );
    }

    @Transactional
    public void markDeleted(Long userId, UUID methodId) {
        lockUser(userId);
        List<SavedPaymentMethod> methods = methodRepository.findByUserIdForUpdate(userId);
        SavedPaymentMethod method = methods.stream()
                .filter(candidate -> candidate.getId().equals(methodId))
                .findFirst()
                .orElseThrow(() -> new BusinessException(ErrorCode.SAVED_CARD_NOT_FOUND));
        method.markDeleted();
        normalizeDefault(methods);
    }

    @Transactional
    public SavedPaymentMethod makeDefault(Long userId, UUID methodId) {
        lockUser(userId);
        List<SavedPaymentMethod> methods = methodRepository.findByUserIdForUpdate(userId);
        SavedPaymentMethod selected = methods.stream()
                .filter(method -> method.getId().equals(methodId))
                .filter(method -> method.getStatus() == SavedPaymentMethodStatus.ACTIVE)
                .findFirst()
                .orElseThrow(() -> new BusinessException(ErrorCode.SAVED_CARD_NOT_FOUND));
        methods.forEach(method -> method.setDefault(false));
        methodRepository.flush();
        selected.setDefault(true);
        methodRepository.flush();
        return selected;
    }

    private PaymentProviderCustomer requireOrCreateCustomer(User user, String customerKey) {
        String fingerprint = dataCipher.fingerprint(customerKey);
        PaymentProviderCustomer existing = customerRepository.findById(user.getId()).orElse(null);
        if (existing != null) {
            if (!existing.getProviderCustomerKeyFingerprint().equals(fingerprint)) {
                throw syncFailed();
            }
            return existing;
        }
        return customerRepository.saveAndFlush(new PaymentProviderCustomer(
                user,
                dataCipher.encrypt(customerKey),
                fingerprint
        ));
    }

    private void requireMatchingCustomer(Long userId, String expectedCustomerKey) {
        String normalizedKey = requireProviderValue(expectedCustomerKey);
        PaymentProviderCustomer customer = customerRepository.findById(userId)
                .orElseThrow(this::syncFailed);
        if (!customer.getProviderCustomerKeyFingerprint().equals(dataCipher.fingerprint(normalizedKey))) {
            throw syncFailed();
        }
    }

    private SavedPaymentMethod upsert(
            User user,
            List<SavedPaymentMethod> methods,
            ProviderCardDetails providerCard
    ) {
        String cardToken = requireProviderValue(providerCard.cardToken());
        String fingerprint = dataCipher.fingerprint(cardToken);
        SavedCardMetadata metadata = toMetadata(providerCard);
        SavedPaymentMethod existing = methods.stream()
                .filter(method -> method.getProviderCardTokenFingerprint().equals(fingerprint))
                .findFirst()
                .orElse(null);
        if (existing != null) {
            existing.refreshMetadata(metadata);
            return existing;
        }

        SavedPaymentMethod created = new SavedPaymentMethod(
                user,
                dataCipher.encrypt(cardToken),
                fingerprint,
                metadata,
                methods.stream().noneMatch(this::isActiveDefault)
        );
        methodRepository.save(created);
        methods.add(created);
        return created;
    }

    private SavedCardMetadata toMetadata(ProviderCardDetails card) {
        try {
            return new SavedCardMetadata(
                    optionalValue(card.alias(), MAX_ALIAS_LENGTH),
                    optionalValue(card.bankName(), MAX_BANK_NAME_LENGTH),
                    optionalValue(card.bankCode(), MAX_BANK_CODE_LENGTH),
                    optionalValue(card.cardFamily(), MAX_CARD_FAMILY_LENGTH),
                    optionalValue(card.cardAssociation(), MAX_CARD_CLASSIFICATION_LENGTH),
                    optionalValue(card.cardType(), MAX_CARD_CLASSIFICATION_LENGTH),
                    requireLastFourDigits(card.lastFourDigits()),
                    optionalValue(card.cardHolderName(), MAX_CARD_HOLDER_LENGTH),
                    validateExpiryMonth(card.expiryMonth()),
                    validateExpiryYear(card.expiryYear())
            );
        } catch (IllegalArgumentException exception) {
            throw syncFailed();
        }
    }

    private void normalizeDefault(List<SavedPaymentMethod> methods) {
        List<SavedPaymentMethod> activeMethods = methods.stream()
                .filter(method -> method.getStatus() == SavedPaymentMethodStatus.ACTIVE)
                .sorted(Comparator.comparing(SavedPaymentMethod::getCreatedAt,
                        Comparator.nullsLast(Comparator.naturalOrder())))
                .toList();
        SavedPaymentMethod selected = activeMethods.stream()
                .filter(SavedPaymentMethod::isDefaultMethod)
                .findFirst()
                .orElse(activeMethods.isEmpty() ? null : activeMethods.get(0));
        methods.forEach(method -> method.setDefault(false));
        methodRepository.flush();
        if (selected != null) {
            selected.setDefault(true);
        }
    }

    private boolean isActiveDefault(SavedPaymentMethod method) {
        return method.getStatus() == SavedPaymentMethodStatus.ACTIVE && method.isDefaultMethod();
    }

    private User lockUser(Long userId) {
        return userRepository.findByIdForUpdate(userId)
                .orElseThrow(() -> new BusinessException(ErrorCode.USER_NOT_FOUND));
    }

    private String requireCustomerKey(Long userId) {
        return customerRepository.findById(userId)
                .map(this::decryptCustomerKey)
                .orElseThrow(() -> new BusinessException(ErrorCode.SAVED_CARD_NOT_FOUND));
    }

    private String decryptCustomerKey(PaymentProviderCustomer customer) {
        try {
            return dataCipher.decrypt(customer.getProviderCustomerKeyEncrypted());
        } catch (RuntimeException exception) {
            throw syncFailed();
        }
    }

    private String decryptCardToken(SavedPaymentMethod method) {
        try {
            return dataCipher.decrypt(method.getProviderCardTokenEncrypted());
        } catch (RuntimeException exception) {
            throw syncFailed();
        }
    }

    private String requireProviderValue(String value) {
        if (isBlank(value) || value.trim().length() > MAX_PROVIDER_KEY_LENGTH) {
            throw syncFailed();
        }
        return value.trim();
    }

    private String requireLastFourDigits(String value) {
        if (value == null || value.length() != 4 || !value.chars().allMatch(Character::isDigit)) {
            throw syncFailed();
        }
        return value;
    }

    private String optionalValue(String value, int maxLength) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > maxLength) {
            throw syncFailed();
        }
        return normalized;
    }

    private Short validateExpiryMonth(Integer value) {
        if (value != null && (value < 1 || value > 12)) {
            throw syncFailed();
        }
        return value == null ? null : value.shortValue();
    }

    private Short validateExpiryYear(Integer value) {
        if (value != null && (value < 2000 || value > 9999)) {
            throw syncFailed();
        }
        return value == null ? null : value.shortValue();
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private BusinessException syncFailed() {
        return new BusinessException(ErrorCode.SAVED_CARD_SYNC_FAILED);
    }
}
