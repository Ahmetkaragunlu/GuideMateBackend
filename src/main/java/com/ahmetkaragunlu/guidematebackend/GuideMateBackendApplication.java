package com.ahmetkaragunlu.guidematebackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.Locale;

@SpringBootApplication
@EnableJpaAuditing
@EnableScheduling
public class GuideMateBackendApplication {

    public static void main(String[] args) {
        configureProcessLocale();
        SpringApplication.run(GuideMateBackendApplication.class, args);
    }

    static void configureProcessLocale() {
        Locale.setDefault(Locale.ROOT);
    }

}
