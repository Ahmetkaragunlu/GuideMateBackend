package com.ahmetkaragunlu.guidematebackend.user.service;

import com.ahmetkaragunlu.guidematebackend.common.util.EmailNormalizer;
import com.ahmetkaragunlu.guidematebackend.common.validation.PasswordPolicy;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
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
    private final String email;
    private final String password;
    private final String firstName;
    private final String lastName;

    public AdminAccountSeeder(
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            PasswordPolicy passwordPolicy,
            EmailNormalizer emailNormalizer,
            @Value("${auth.admin-seed.email}") String email,
            @Value("${auth.admin-seed.password}") String password,
            @Value("${auth.admin-seed.first-name:GuideMate}") String firstName,
            @Value("${auth.admin-seed.last-name:Admin}") String lastName
    ) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.emailNormalizer = emailNormalizer;
        this.email = email;
        this.password = password;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        String normalizedEmail = emailNormalizer.normalize(email);
        if (normalizedEmail == null || normalizedEmail.isBlank()) {
            throw new IllegalStateException("ADMIN_EMAIL is required when admin seed is enabled");
        }

        User existingUser = userRepository.findByEmailWithRole(normalizedEmail).orElse(null);
        if (existingUser != null) {
            if (existingUser.getRole() == null
                    || !RoleType.ROLE_ADMIN.name().equals(existingUser.getRole().getName())
                    || existingUser.getAccountStatus() != AccountStatus.ACTIVE) {
                throw new IllegalStateException("Admin seed email is not an active admin account");
            }
            return;
        }

        if (password == null || password.isBlank()) {
            throw new IllegalStateException("ADMIN_PASSWORD is required when admin seed is enabled");
        }
        passwordPolicy.validate(password);
        Role adminRole = roleRepository.findByName(RoleType.ROLE_ADMIN.name())
                .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN is missing"));

        User admin = new User();
        admin.setEmail(normalizedEmail);
        admin.setPassword(passwordEncoder.encode(password));
        admin.setFirstName(firstName.strip());
        admin.setLastName(lastName.strip());
        admin.setAccountStatus(AccountStatus.ACTIVE);
        admin.setRole(adminRole);
        admin.setRoleSelected(true);
        userRepository.save(admin);
    }
}
