package com.ahmetkaragunlu.guidematebackend.user.service;

import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.user.config.AdminAccountSeedProperties;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@ConditionalOnProperty(prefix = "auth.admin-seed", name = "enabled", havingValue = "true")
public class AdminAccountSeeder implements ApplicationRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final EmailNormalizer emailNormalizer;
    private final AdminAccountSeedProperties properties;

    public AdminAccountSeeder(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicy passwordPolicy,
            EmailNormalizer emailNormalizer,
            AdminAccountSeedProperties properties
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.emailNormalizer = emailNormalizer;
        this.properties = properties;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        String normalizedEmail = emailNormalizer.normalize(properties.email());
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            throw new IllegalStateException("ADMIN_EMAIL is required when admin seed is enabled");
        }

        User existingUser = userRepository.findByEmailWithRole(normalizedEmail).orElse(null);
        if (existingUser != null) {
            if (!existingUser.hasRole(RoleType.ROLE_ADMIN)
                    || existingUser.getAccountStatus() != AccountStatus.ACTIVE) {
                throw new IllegalStateException("Admin seed email is not an active admin account");
            }
            return;
        }

        passwordPolicy.validate(properties.password());
        Role adminRole = roleRepository.findByName(RoleType.ROLE_ADMIN.name())
                .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN is missing"));

        User admin = new User(
                properties.firstName().strip(),
                properties.lastName().strip(),
                normalizedEmail,
                passwordEncoder.encode(properties.password())
        );
        admin.activate();
        admin.selectRole(adminRole);
        userRepository.save(admin);
    }
}
