package com.ahmetkaragunlu.guidematebackend.wallet.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AddBankAccountRequest(
        @NotBlank(message = "{validation.iban.notBlank}")
        @Size(max = 34, message = "{validation.iban.size}")
        String iban,
        @NotBlank(message = "{validation.accountHolder.notBlank}")
        @Size(max = 160, message = "{validation.accountHolder.size}")
        String accountHolderName
) {
}
