package com.ahmetkaragunlu.guidematebackend.payment.controller;

import com.ahmetkaragunlu.guidematebackend.payment.domain.Payment;
import com.ahmetkaragunlu.guidematebackend.payment.dto.IyzicoWebhookRequest;
import com.ahmetkaragunlu.guidematebackend.payment.dto.PaymentCallbackResponse;
import com.ahmetkaragunlu.guidematebackend.payment.service.IyzicoWebhookService;
import com.ahmetkaragunlu.guidematebackend.payment.service.PaymentVerificationService;
import io.swagger.v3.oas.annotations.Hidden;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Hidden
@RestController
@RequestMapping("/api/v1/payments/iyzico")
@RequiredArgsConstructor
public class IyzicoPaymentController {

    private final PaymentVerificationService paymentVerificationService;
    private final IyzicoWebhookService webhookService;

    @PostMapping(value = "/callback", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<PaymentCallbackResponse> callback(@RequestParam("token") String token) {
        Payment payment = paymentVerificationService.verifyToken(token, "CALLBACK", token);
        return ResponseEntity.ok(new PaymentCallbackResponse(payment.getId(), payment.getStatus()));
    }

    @PostMapping("/webhook")
    public ResponseEntity<Void> webhook(
            @RequestHeader("X-IYZ-SIGNATURE-V3") String signature,
            @RequestBody IyzicoWebhookRequest request
    ) {
        webhookService.handle(signature, request);
        return ResponseEntity.ok().build();
    }
}
