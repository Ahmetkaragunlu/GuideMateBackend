package com.ahmetkaragunlu.guidematebackend.payment.repository;

import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface PaymentEventRepository extends JpaRepository<PaymentEvent, UUID> {

    boolean existsByProviderEventId(String providerEventId);
}
