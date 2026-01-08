package com.ahmetkaragunlu.guidematebackend.common.config;



import com.ahmetkaragunlu.guidematebackend.user.domain.Role;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;

    @Override
    @Transactional
    public void run(String @NonNull ... args) {

        for (RoleType roleType : RoleType.values()) {
            String roleName = roleType.name();
            if (roleRepository.findByName(roleName).isEmpty()) {
                // Yoksa kaydet (String olarak kaydeder)
                roleRepository.save(new Role(roleName));
                System.out.println("Role eklendi: " + roleName);
            }
        }
    }
}