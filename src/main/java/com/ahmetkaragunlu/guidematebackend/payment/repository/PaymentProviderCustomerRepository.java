package com.ahmetkaragunlu.guidematebackend.payment.repository;

import com.ahmetkaragunlu.guidematebackend.payment.domain.provider.PaymentProviderCustomer;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentProviderCustomerRepository extends JpaRepository<PaymentProviderCustomer, Long> {
}
