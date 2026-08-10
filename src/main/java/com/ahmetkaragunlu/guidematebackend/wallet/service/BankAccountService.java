package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccount;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccountStatus;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.BankAccountRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class BankAccountService {

    private final BankAccountRepository bankAccountRepository;
    private final TurkishIbanPolicy ibanPolicy;
    private final SensitiveDataCipher dataCipher;

    @Transactional(readOnly = true)
    public Page<BankAccount> getActiveAccounts(User guide, int page, int size) {
        requireGuide(guide);
        return bankAccountRepository.findByGuide_IdAndStatusOrderByDefaultAccountDescCreatedAtAsc(
                guide.getId(),
                BankAccountStatus.ACTIVE,
                PageRequest.of(page, size)
        );
    }

    @Transactional
    public BankAccount add(User guide, String iban, String accountHolderName) {
        requireGuide(guide);
        String normalizedHolder = normalizeHolder(accountHolderName);
        ValidatedIban validatedIban = ibanPolicy.validate(iban);
        String fingerprint = dataCipher.fingerprint(validatedIban.normalizedIban());
        if (bankAccountRepository.existsByGuide_IdAndIbanFingerprint(guide.getId(), fingerprint)) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_ALREADY_EXISTS);
        }
        boolean makeDefault = !bankAccountRepository.existsByGuide_IdAndStatus(
                guide.getId(),
                BankAccountStatus.ACTIVE
        );
        BankAccount account = new BankAccount(
                guide,
                dataCipher.encrypt(validatedIban.normalizedIban()),
                fingerprint,
                validatedIban.maskedIban(),
                validatedIban.bankCode(),
                validatedIban.bankName(),
                normalizedHolder,
                makeDefault
        );
        try {
            return bankAccountRepository.saveAndFlush(account);
        } catch (DataIntegrityViolationException exception) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_ALREADY_EXISTS, exception);
        }
    }

    @Transactional
    public BankAccount makeDefault(User guide, UUID accountId) {
        requireGuide(guide);
        BankAccount target = requireOwnedActiveForUpdate(guide, accountId);
        if (target.isDefaultAccount()) {
            return target;
        }
        bankAccountRepository.findDefaultForUpdate(guide.getId(), BankAccountStatus.ACTIVE)
                .ifPresent(account -> account.setDefault(false));
        bankAccountRepository.flush();
        target.setDefault(true);
        return target;
    }

    @Transactional
    public void delete(User guide, UUID accountId) {
        requireGuide(guide);
        BankAccount account = requireOwnedActiveForUpdate(guide, accountId);
        boolean wasDefault = account.isDefaultAccount();
        account.disable();
        bankAccountRepository.flush();
        if (wasDefault) {
            bankAccountRepository.findByGuide_IdAndStatusOrderByDefaultAccountDescCreatedAtAsc(
                            guide.getId(),
                            BankAccountStatus.ACTIVE
                    ).stream()
                    .findFirst()
                    .ifPresent(next -> next.setDefault(true));
        }
    }

    public BankAccount requireOwnedActiveForUpdate(User guide, UUID accountId) {
        BankAccount account = bankAccountRepository.findOwnedByIdForUpdate(accountId, guide.getId())
                .orElseThrow(() -> new BusinessException(ErrorCode.BANK_ACCOUNT_NOT_FOUND));
        if (account.getStatus() != BankAccountStatus.ACTIVE) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_NOT_FOUND);
        }
        return account;
    }

    private String normalizeHolder(String value) {
        if (value == null || value.isBlank()) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_INVALID);
        }
        String normalized = value.trim().replaceAll("\\s+", " ");
        if (normalized.length() > 160) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_INVALID);
        }
        return normalized;
    }

    private void requireGuide(User user) {
        if (user.getRole() == null || !RoleType.ROLE_GUIDE.name().equals(user.getRole().getName())) {
            throw new BusinessException(ErrorCode.FORBIDDEN);
        }
    }
}
