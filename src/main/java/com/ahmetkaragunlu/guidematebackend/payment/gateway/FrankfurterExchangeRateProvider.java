package com.ahmetkaragunlu.guidematebackend.payment.gateway;

import com.ahmetkaragunlu.guidematebackend.payment.config.PaymentProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.math.BigDecimal;
import java.time.LocalDate;

@Component
@RequiredArgsConstructor
public class FrankfurterExchangeRateProvider implements ExchangeRateProvider {

    private final RestClient fxRestClient;
    private final PaymentProperties properties;

    @Override
    public ExchangeRate latest(String baseCurrencyCode, String chargeCurrencyCode) {
        try {
            RateResponse response = fxRestClient.get()
                    .uri(uriBuilder -> uriBuilder
                            .path("/v2/rate/{base}/{charge}")
                            .queryParam("providers", properties.fx().rateProvider())
                            .build(baseCurrencyCode, chargeCurrencyCode))
                    .retrieve()
                    .body(RateResponse.class);
            if (response == null
                    || response.date() == null
                    || response.rate() == null
                    || response.rate().signum() <= 0
                    || !baseCurrencyCode.equalsIgnoreCase(response.base())
                    || !chargeCurrencyCode.equalsIgnoreCase(response.quote())) {
                throw new ExchangeRateUnavailableException();
            }
            return new ExchangeRate(
                    baseCurrencyCode,
                    chargeCurrencyCode,
                    response.rate(),
                    "FRANKFURTER_" + properties.fx().rateProvider(),
                    response.date()
            );
        } catch (ExchangeRateUnavailableException exception) {
            throw exception;
        } catch (RestClientException | IllegalArgumentException exception) {
            throw new ExchangeRateUnavailableException(exception);
        }
    }

    private record RateResponse(
            LocalDate date,
            String base,
            String quote,
            BigDecimal rate
    ) {
    }
}
