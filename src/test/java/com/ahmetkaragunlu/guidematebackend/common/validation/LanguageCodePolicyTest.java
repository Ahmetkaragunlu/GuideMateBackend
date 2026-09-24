package com.ahmetkaragunlu.guidematebackend.common.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LanguageCodePolicyTest {

    private final LanguageCodePolicy policy = new LanguageCodePolicy();

    @Test
    void normalizesCaseWhitespaceAndDuplicatesWhilePreservingInputOrder() {
        Set<String> result = policy.normalize(List.of(" TR ", "en", "tr", "fra"));

        assertThat(result).containsExactly("tr", "en", "fra");
    }

    @ParameterizedTest
    @NullAndEmptySource
    void returnsEmptySetWhenOptionalLanguagesAreAbsent(Collection<String> languageCodes) {
        assertThat(policy.normalizeOptional(languageCodes)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "und", "not-a-language"})
    void rejectsBlankUndefinedOrUnsupportedLanguageCode(String languageCode) {
        assertThatThrownBy(() -> policy.normalize(List.of(languageCode)))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_LANGUAGE_CODE)
                );
    }

    @Test
    void rejectsRequiredEmptyLanguageCollection() {
        assertThatThrownBy(() -> policy.normalize(List.of()))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.INVALID_LANGUAGE_CODE)
                );
    }
}
