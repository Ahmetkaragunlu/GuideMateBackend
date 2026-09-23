package com.ahmetkaragunlu.guidematebackend.user.domain;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
class UserEqualityIntegrationTest {

    @Autowired
    private EntityManager entityManager;

    @Test
    @Transactional
    void comparesHibernateProxyByNaturalEmailKey() {
        String email = "proxy-" + UUID.randomUUID() + "@example.com";
        User persisted = new User("Proxy", "User", email, "not-used");
        entityManager.persist(persisted);
        entityManager.flush();
        Long id = persisted.getId();
        entityManager.clear();

        User proxy = entityManager.getReference(User.class, id);
        User sameNaturalKey = new User("Another", "Name", email, "different-hash");

        assertThat(proxy).isEqualTo(sameNaturalKey);
        assertThat(proxy.hashCode()).isEqualTo(sameNaturalKey.hashCode());
    }
}
