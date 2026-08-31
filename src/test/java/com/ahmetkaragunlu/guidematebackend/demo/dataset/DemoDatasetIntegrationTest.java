package com.ahmetkaragunlu.guidematebackend.demo.dataset;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties =
        "spring.datasource.url=jdbc:tc:postgresql:18-alpine:///guidemate_demo_dataset_test")
@ActiveProfiles("test")
@Transactional
class DemoDatasetIntegrationTest {

    @Autowired
    private DemoDatasetWriter datasetWriter;
    @Autowired
    private DemoDatasetVerifier datasetVerifier;
    @Autowired
    private DemoBankFixtures bankFixtures;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void writesTheCompleteDatasetWithoutBypassingDatabaseConstraints() {
        datasetVerifier.requireEmptyTarget();

        datasetWriter.write(
                passwordEncoder.encode(DemoTestFixtures.PASSWORD),
                DemoTestFixtures.REFERENCE_INSTANT,
                DemoTestFixtures.mediaFixtures(),
                bankFixtures.create()
        );

        datasetVerifier.verify(DemoTestFixtures.REFERENCE_INSTANT);
    }
}
