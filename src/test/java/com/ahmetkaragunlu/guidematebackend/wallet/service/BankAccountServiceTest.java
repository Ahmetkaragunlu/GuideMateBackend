package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.BankAccount;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.BankAccountRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BankAccountServiceTest {

    @Mock private BankAccountRepository repository;
    @Mock private TurkishIbanPolicy ibanPolicy;
    @Mock private SensitiveDataCipher dataCipher;
    @Mock private User guide;
    private BankAccountService service;

    @BeforeEach
    void setUp() {
        service = new BankAccountService(repository, ibanPolicy, dataCipher);
    }

    @Test
    void storesEncryptedIbanAndMakesFirstAccountDefault() {
        when(guide.hasRole(RoleType.ROLE_GUIDE)).thenReturn(true);
        when(guide.getId()).thenReturn(42L);
        when(ibanPolicy.validate("TR iban")).thenReturn(
                new ValidatedIban("TR000000000000000000000000", "TR00 **** 0000", "00000", "Test Bank")
        );
        when(dataCipher.fingerprint("TR000000000000000000000000")).thenReturn("fingerprint");
        when(dataCipher.encrypt("TR000000000000000000000000")).thenReturn("encrypted");
        ArgumentCaptor<BankAccount> account = ArgumentCaptor.forClass(BankAccount.class);
        when(repository.saveAndFlush(account.capture())).thenAnswer(invocation -> invocation.getArgument(0));

        BankAccount result = service.add(guide, "TR iban", "  Ahmet   Karagunlu  ");

        assertThat(result.getIbanEncrypted()).isEqualTo("encrypted");
        assertThat(result.getAccountHolderName()).isEqualTo("Ahmet Karagunlu");
        assertThat(result.isDefaultAccount()).isTrue();
    }

    @Test
    void rejectsNonGuideBeforeReadingSensitiveInput() {
        when(guide.hasRole(RoleType.ROLE_GUIDE)).thenReturn(false);

        assertThatThrownBy(() -> service.add(guide, "TR iban", "Test User"))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        verify(ibanPolicy, never()).validate(any());
    }
}
