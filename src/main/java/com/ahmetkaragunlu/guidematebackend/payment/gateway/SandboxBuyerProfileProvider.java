package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SandboxBuyerProfileProvider implements BuyerProfileProvider {

    private final PaymentProperties properties;

    @Override
    public BuyerProfile get(User user) {
        PaymentProperties.SandboxBuyer sandbox = properties.sandboxBuyer();
        if (!sandbox.enabled()) {
            throw new BusinessException(ErrorCode.PAYMENT_INITIALIZATION_FAILED);
        }
        return new BuyerProfile(
                "guidemate-user-" + user.getId(),
                user.getFirstName(),
                user.getLastName(),
                user.getEmail(),
                sandbox.identityNumber(),
                sandbox.phoneNumber(),
                sandbox.address(),
                sandbox.city(),
                sandbox.country(),
                sandbox.zipCode(),
                sandbox.ipAddress()
        );
    }
}
