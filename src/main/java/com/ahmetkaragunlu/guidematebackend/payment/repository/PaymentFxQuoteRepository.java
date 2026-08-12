package com.ahmetkaragunlu.guidematebackend.payment.repository;

import com.ahmetkaragunlu.guidematebackend.payment.domain.PaymentFxQuote;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface PaymentFxQuoteRepository extends JpaRepository<PaymentFxQuote, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT quote FROM PaymentFxQuote quote WHERE quote.id = :quoteId")
    Optional<PaymentFxQuote> findByIdForUpdate(@Param("quoteId") UUID quoteId);
}
