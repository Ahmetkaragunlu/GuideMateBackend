package com.ahmetkaragunlu.guidematebackend.wallet.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Map;

@Component
public class TurkishIbanPolicy {

    private static final int TURKISH_IBAN_LENGTH = 26;
    private static final Map<String, String> BANKS_BY_CODE = Map.ofEntries(
            Map.entry("00215", "Adil Katilim Bankasi"),
            Map.entry("00046", "Akbank"),
            Map.entry("00143", "Aktif Yatirim Bankasi"),
            Map.entry("00203", "Albaraka Turk Katilim Bankasi"),
            Map.entry("00124", "Alternatifbank"),
            Map.entry("00135", "Anadolubank"),
            Map.entry("00091", "Arap Turk Bankasi"),
            Map.entry("00161", "Aytemiz Yatirim Bankasi"),
            Map.entry("00129", "Bank of America Yatirim Bank"),
            Map.entry("00149", "Bank of China Turkey"),
            Map.entry("00142", "BankPozitif"),
            Map.entry("00029", "Birlesik Fon Bankasi"),
            Map.entry("00125", "Burgan Bank"),
            Map.entry("00092", "Citibank"),
            Map.entry("00158", "Colendi Bank"),
            Map.entry("00151", "D Yatirim Bankasi"),
            Map.entry("00134", "DenizBank"),
            Map.entry("00152", "Destek Yatirim Bankasi"),
            Map.entry("00115", "Deutsche Bank"),
            Map.entry("00138", "Diler Yatirim Bankasi"),
            Map.entry("00214", "Dunya Katilim Bankasi"),
            Map.entry("00157", "Enpara Bank"),
            Map.entry("00103", "Fibabanka"),
            Map.entry("00159", "FUPS Bank"),
            Map.entry("00150", "Golden Global Yatirim Bankasi"),
            Map.entry("00139", "GSD Yatirim Bankasi"),
            Map.entry("00212", "Hayat Finans Katilim Bankasi"),
            Map.entry("00156", "Hedef Yatirim Bankasi"),
            Map.entry("00123", "HSBC"),
            Map.entry("00109", "ICBC Turkey Bank"),
            Map.entry("00099", "ING"),
            Map.entry("00148", "Intesa Sanpaolo"),
            Map.entry("00004", "Iller Bankasi"),
            Map.entry("00132", "Takasbank"),
            Map.entry("00098", "JPMorgan Chase Bank"),
            Map.entry("00205", "Kuveyt Turk Katilim Bankasi"),
            Map.entry("00806", "Merkezi Kayit Kurulusu"),
            Map.entry("00153", "Misyon Yatirim Bankasi"),
            Map.entry("00147", "MUFG Bank Turkey"),
            Map.entry("00141", "Nurol Yatirim Bankasi"),
            Map.entry("00146", "Odea Bank"),
            Map.entry("00116", "Pasha Yatirim Bankasi"),
            Map.entry("00807", "PTT"),
            Map.entry("00137", "Rabobank"),
            Map.entry("00122", "Societe Generale"),
            Map.entry("00121", "Standard Chartered Yatirim Bankasi"),
            Map.entry("00059", "Sekerbank"),
            Map.entry("00032", "Turk Ekonomi Bankasi"),
            Map.entry("00016", "Turk Eximbank"),
            Map.entry("00062", "Garanti BBVA"),
            Map.entry("00012", "Halkbank"),
            Map.entry("00064", "Turkiye Is Bankasi"),
            Map.entry("00017", "Turkiye Kalkinma ve Yatirim Bankasi"),
            Map.entry("00014", "Turkiye Sinai Kalkinma Bankasi"),
            Map.entry("00015", "VakifBank"),
            Map.entry("00001", "Turkiye Cumhuriyet Merkez Bankasi"),
            Map.entry("00010", "Ziraat Bankasi"),
            Map.entry("00154", "Tera Yatirim Bankasi"),
            Map.entry("00213", "T.O.M. Katilim Bankasi"),
            Map.entry("00096", "Turkish Bank"),
            Map.entry("00108", "Turkland Bank"),
            Map.entry("00060", "Turk Ticaret Bankasi"),
            Map.entry("00211", "Turkiye Emlak Katilim Bankasi"),
            Map.entry("00206", "Turkiye Finans Katilim Bankasi"),
            Map.entry("00210", "Vakif Katilim Bankasi"),
            Map.entry("00067", "Yapi Kredi"),
            Map.entry("00160", "Ziraat Dinamik Banka"),
            Map.entry("00209", "Ziraat Katilim Bankasi"),
            Map.entry("00155", "Q Yatirim Bankasi"),
            Map.entry("00111", "QNB")
    );

    public ValidatedIban validate(String value) {
        String iban = normalize(value);
        if (iban.length() != TURKISH_IBAN_LENGTH
                || !iban.startsWith("TR")
                || !iban.substring(2, 4).chars().allMatch(Character::isDigit)
                || iban.charAt(9) != '0'
                || !iban.substring(10).chars().allMatch(this::isAsciiAlphaNumeric)
                || mod97(iban.substring(4) + iban.substring(0, 4)) != 1) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_INVALID);
        }
        String bankCode = iban.substring(4, 9);
        String bankName = BANKS_BY_CODE.get(bankCode);
        if (bankName == null) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_INVALID);
        }
        return new ValidatedIban(
                iban,
                iban.substring(0, 4) + " **** **** **** **** **" + iban.substring(22),
                bankCode,
                bankName
        );
    }

    private String normalize(String value) {
        if (value == null) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_INVALID);
        }
        String normalized = value.replace(" ", "").toUpperCase(Locale.ROOT);
        if (!normalized.chars().allMatch(this::isAsciiAlphaNumeric)) {
            throw new BusinessException(ErrorCode.BANK_ACCOUNT_INVALID);
        }
        return normalized;
    }

    private int mod97(String value) {
        int remainder = 0;
        for (char character : value.toCharArray()) {
            String numeric = character >= '0' && character <= '9'
                    ? Character.toString(character)
                    : Integer.toString(character - 'A' + 10);
            for (char digit : numeric.toCharArray()) {
                remainder = (remainder * 10 + digit - '0') % 97;
            }
        }
        return remainder;
    }

    private boolean isAsciiAlphaNumeric(int character) {
        return character >= '0' && character <= '9' || character >= 'A' && character <= 'Z';
    }
}
