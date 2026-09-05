package com.ahmetkaragunlu.guidematebackend;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;

import java.util.Locale;

import static org.assertj.core.api.Assertions.assertThat;

@ResourceLock(Resources.LOCALE)
class GuideMateBackendApplicationTest {

    @Test
    void configuresLocaleIndependentProcessDefaults() {
        Locale previousDefault = Locale.getDefault();
        Locale previousDisplay = Locale.getDefault(Locale.Category.DISPLAY);
        Locale previousFormat = Locale.getDefault(Locale.Category.FORMAT);
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"));

            GuideMateBackendApplication.configureProcessLocale();

            assertThat(Locale.getDefault()).isEqualTo(Locale.ROOT);
        } finally {
            Locale.setDefault(previousDefault);
            Locale.setDefault(Locale.Category.DISPLAY, previousDisplay);
            Locale.setDefault(Locale.Category.FORMAT, previousFormat);
        }
    }
}
