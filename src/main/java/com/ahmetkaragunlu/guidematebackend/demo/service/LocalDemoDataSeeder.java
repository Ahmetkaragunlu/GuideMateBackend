package com.ahmetkaragunlu.guidematebackend.demo.service;

import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.demo.config.DemoSeedProperties;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Profile("local")
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "demo.seed", name = "enabled", havingValue = "true")
public class LocalDemoDataSeeder implements ApplicationRunner {

    private final DemoSeedProperties properties;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final GuideProfileRepository guideProfileRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final EmailNormalizer emailNormalizer;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        passwordPolicy.validate(properties.password());
        User guide = ensureUser(
                properties.guideEmail(),
                "Demo",
                "Guide",
                RoleType.ROLE_GUIDE
        );
        ensureUser(
                properties.touristEmail(),
                "Demo",
                "Tourist",
                RoleType.ROLE_TOURIST
        );
        if (!guideProfileRepository.existsById(guide.getId())) {
            guideProfileRepository.save(GuideProfile.create(
                    guide,
                    "Local Experience Guide",
                    "Idempotent demo guide profile for GuideMate local network flows.",
                    Set.of("eng", "tur")
            ));
        }
    }

    private User ensureUser(
            String email,
            String firstName,
            String lastName,
            RoleType roleType
    ) {
        String normalizedEmail = emailNormalizer.normalize(email);
        User existing = userRepository.findByEmailWithRole(normalizedEmail).orElse(null);
        if (existing != null) {
            requireExpectedAccount(existing, roleType);
            return existing;
        }

        Role role = roleRepository.findByName(roleType.name())
                .orElseThrow(() -> new IllegalStateException(roleType.name() + " is missing"));
        User user = new User();
        user.setEmail(normalizedEmail);
        user.setPassword(passwordEncoder.encode(properties.password()));
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setRole(role);
        user.setRoleSelected(true);
        user.setAccountStatus(AccountStatus.ACTIVE);
        return userRepository.save(user);
    }

    private void requireExpectedAccount(User user, RoleType roleType) {
        if (user.getRole() == null
                || !roleType.name().equals(user.getRole().getName())
                || user.getAccountStatus() != AccountStatus.ACTIVE) {
            throw new IllegalStateException(
                    "Demo seed email belongs to an incompatible existing account"
            );
        }
    }
}
