package com.ahmetkaragunlu.guidematebackend.auth.service;

import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
class RegistrationConflictVerifier {

    private final UserRepository userRepository;

    @Transactional(propagation = Propagation.REQUIRES_NEW, readOnly = true)
    public boolean emailExists(String normalizedEmail) {
        return userRepository.findByEmail(normalizedEmail).isPresent();
    }
}
