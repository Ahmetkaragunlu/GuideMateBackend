package com.ahmetkaragunlu.guidematebackend.common.validation;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class LanguageCodePolicy {

    private static final String UNDEFINED_LANGUAGE_CODE = "und";
    private static final Set<String> SUPPORTED_CODES = supportedCodes();

    public Set<String> normalize(Collection<String> languageCodes) {
        Set<String> normalized = languageCodes.stream()
                .map(code -> code.trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (normalized.isEmpty() || normalized.stream().anyMatch(code -> !SUPPORTED_CODES.contains(code))) {
            throw new BusinessException(ErrorCode.INVALID_LANGUAGE_CODE);
        }
        return normalized;
    }

    public Set<String> normalizeOptional(Collection<String> languageCodes) {
        if (languageCodes == null || languageCodes.isEmpty()) {
            return Set.of();
        }
        return normalize(languageCodes);
    }

    private static Set<String> supportedCodes() {
        Set<String> codes = Arrays.stream(Locale.getISOLanguages())
                .map(code -> code.toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
        for (Locale locale : Locale.getAvailableLocales()) {
            try {
                String code = locale.getISO3Language().toLowerCase(Locale.ROOT);
                if (!code.isBlank()) {
                    codes.add(code);
                }
            } catch (MissingResourceException ignored) {
                // Not every runtime locale has an ISO-639-2 code.
            }
        }
        codes.remove(UNDEFINED_LANGUAGE_CODE);
        return Set.copyOf(codes);
    }
}
