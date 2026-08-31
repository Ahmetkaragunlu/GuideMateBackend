package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.demo.config.DemoDatasetProperties;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

@Profile("demo")
@Component
@ConditionalOnProperty(prefix = "demo.dataset", name = "enabled", havingValue = "true")
class DemoDatasetSeeder implements ApplicationRunner {

    private final DemoDatasetProperties properties;
    private final PasswordPolicy passwordPolicy;
    private final PasswordEncoder passwordEncoder;
    private final DemoMediaFixtures mediaFixtures;
    private final DemoBankFixtures bankFixtures;
    private final DemoDatasetWriter datasetWriter;
    private final DemoDatasetVerifier datasetVerifier;
    private final TransactionTemplate transactionTemplate;

    DemoDatasetSeeder(
            DemoDatasetProperties properties,
            PasswordPolicy passwordPolicy,
            PasswordEncoder passwordEncoder,
            DemoMediaFixtures mediaFixtures,
            DemoBankFixtures bankFixtures,
            DemoDatasetWriter datasetWriter,
            DemoDatasetVerifier datasetVerifier,
            TransactionTemplate transactionTemplate
    ) {
        this.properties = properties;
        this.passwordPolicy = passwordPolicy;
        this.passwordEncoder = passwordEncoder;
        this.mediaFixtures = mediaFixtures;
        this.bankFixtures = bankFixtures;
        this.datasetWriter = datasetWriter;
        this.datasetVerifier = datasetVerifier;
        this.transactionTemplate = transactionTemplate;
    }

    @Override
    public void run(ApplicationArguments arguments) {
        passwordPolicy.validate(properties.password());
        if (datasetVerifier.isAlreadySeeded()) {
            datasetVerifier.verify(properties.referenceInstant());
            return;
        }
        datasetVerifier.requireEmptyTarget();

        List<DemoFixtureData.Media> media = mediaFixtures.prepare();
        List<DemoFixtureData.BankAccount> bankAccounts = bankFixtures.create();
        transactionTemplate.executeWithoutResult(status -> datasetWriter.write(
                passwordEncoder.encode(properties.password()),
                properties.referenceInstant(),
                media,
                bankAccounts
        ));

        datasetVerifier.verify(properties.referenceInstant());
        mediaFixtures.verify(media);
    }
}
