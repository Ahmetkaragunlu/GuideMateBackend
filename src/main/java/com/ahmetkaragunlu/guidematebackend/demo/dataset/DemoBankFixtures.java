package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import com.ahmetkaragunlu.guidematebackend.common.security.SensitiveDataCipher;
import com.ahmetkaragunlu.guidematebackend.wallet.service.TurkishIbanPolicy;
import com.ahmetkaragunlu.guidematebackend.wallet.service.ValidatedIban;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

@Component
class DemoBankFixtures {

    private static final List<String> BANK_CODES = List.of(
            "00010", "00062", "00064", "00067", "00046"
    );

    private final TurkishIbanPolicy ibanPolicy;
    private final SensitiveDataCipher dataCipher;

    DemoBankFixtures(TurkishIbanPolicy ibanPolicy, SensitiveDataCipher dataCipher) {
        this.ibanPolicy = ibanPolicy;
        this.dataCipher = dataCipher;
    }

    List<DemoFixtureData.BankAccount> create() {
        List<DemoFixtureData.BankAccount> fixtures = new ArrayList<>(55);
        for (long guideId = 2006; guideId <= 2050; guideId++) {
            fixtures.add(create(guideId, 1));
            if (guideId <= 2015) {
                fixtures.add(create(guideId, 2));
            }
        }
        return List.copyOf(fixtures);
    }

    private DemoFixtureData.BankAccount create(long guideId, int ordinal) {
        String bankCode = BANK_CODES.get((int) ((guideId + ordinal) % BANK_CODES.size()));
        String accountNumber = String.format(Locale.ROOT, "%016d", guideId * 10 + ordinal);
        ValidatedIban iban = ibanPolicy.validate(validTurkishIban(bankCode, accountNumber));
        return new DemoFixtureData.BankAccount(
                DemoSeedIds.uuid("bank-account-" + guideId + "-" + ordinal),
                guideId,
                ordinal,
                dataCipher.encrypt(iban.normalizedIban()),
                dataCipher.fingerprint(iban.normalizedIban()),
                iban.maskedIban(),
                iban.bankCode(),
                iban.bankName(),
                "GuideMate Demo Guide " + (guideId - 2000)
        );
    }

    private String validTurkishIban(String bankCode, String accountNumber) {
        String bban = bankCode + "0" + accountNumber;
        int checkDigits = 98 - mod97(bban + "292700");
        return "TR" + String.format(Locale.ROOT, "%02d", checkDigits) + bban;
    }

    private int mod97(String numericValue) {
        int remainder = 0;
        for (int index = 0; index < numericValue.length(); index++) {
            remainder = (remainder * 10 + numericValue.charAt(index) - '0') % 97;
        }
        return remainder;
    }
}
