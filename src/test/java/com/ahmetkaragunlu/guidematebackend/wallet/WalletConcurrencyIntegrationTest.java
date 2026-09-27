package com.ahmetkaragunlu.guidematebackend.wallet;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.support.persistence.PersistenceTestFixtures;
import com.ahmetkaragunlu.guidematebackend.support.persistence.PersistenceTestFixtures.WalletFixture;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.Wallet;
import com.ahmetkaragunlu.guidematebackend.wallet.domain.ledger.LedgerEntryType;
import com.ahmetkaragunlu.guidematebackend.wallet.repository.WalletLedgerRepository;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletAccountService;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletBalance;
import com.ahmetkaragunlu.guidematebackend.wallet.service.account.WalletEntryCommand;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Clock;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static com.ahmetkaragunlu.guidematebackend.support.persistence.ConcurrentTestExecutor.run;
import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Import(PersistenceTestFixtures.class)
class WalletConcurrencyIntegrationTest {

    @Autowired
    private PersistenceTestFixtures fixtures;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private WalletAccountService walletAccountService;
    @Autowired
    private WalletLedgerRepository walletLedgerRepository;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private Clock clock;

    @Test
    void preventsConcurrentWalletOverspend() throws Exception {
        WalletFixture fixture = fixtures.createFundedWallet();

        List<ErrorCode> results = run(
                () -> debit(fixture.userId(), 8_000L, "debit-a-" + UUID.randomUUID()),
                () -> debit(fixture.userId(), 8_000L, "debit-b-" + UUID.randomUUID())
        );

        assertThat(results.stream().filter(Objects::isNull).count()).isEqualTo(1);
        assertThat(results.stream().filter(ErrorCode.INSUFFICIENT_WALLET_BALANCE::equals).count())
                .isEqualTo(1);
        assertThat(walletBalance(fixture.userId()).availableBalanceMinor()).isEqualTo(2_000L);
        assertThat(walletLedgerRepository.findByWallet_IdOrderByOccurredAtDesc(
                fixture.walletId(),
                PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(2);
    }

    @Test
    void appliesConcurrentWalletRetryOnlyOnce() throws Exception {
        WalletFixture fixture = fixtures.createFundedWallet();
        String idempotencyKey = "same-debit-" + UUID.randomUUID();

        List<ErrorCode> results = run(
                () -> debit(fixture.userId(), 3_000L, idempotencyKey),
                () -> debit(fixture.userId(), 3_000L, idempotencyKey)
        );

        assertThat(results).containsOnlyNulls();
        assertThat(walletBalance(fixture.userId()).availableBalanceMinor()).isEqualTo(7_000L);
        assertThat(walletLedgerRepository.findByWallet_IdOrderByOccurredAtDesc(
                fixture.walletId(),
                PageRequest.of(0, 10)
        ).getTotalElements()).isEqualTo(2);
    }

    private ErrorCode debit(Long userId, long amountMinor, String idempotencyKey) {
        try {
            new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
                User user = userRepository.findById(userId).orElseThrow();
                Wallet wallet = walletAccountService.getOrCreateForUpdate(user);
                walletAccountService.debit(
                        wallet,
                        new WalletEntryCommand(
                                amountMinor,
                                LedgerEntryType.TOUR_PURCHASE,
                                "TEST_PURCHASE",
                                UUID.randomUUID(),
                                idempotencyKey,
                                clock.instant()
                        )
                );
                walletLedgerRepository.flush();
            });
            return null;
        } catch (BusinessException exception) {
            return exception.getErrorCode();
        }
    }

    private WalletBalance walletBalance(Long userId) {
        User user = userRepository.findById(userId).orElseThrow();
        return walletAccountService.getBalance(user);
    }
}
