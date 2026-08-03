package com.ahmetkaragunlu.guidematebackend.profile.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.UUID;

public record UpdateGuideProfileRequest(
        @NotBlank(message = "{validation.guide.specialty.notBlank}")
        @Size(min = 2, max = 60, message = "{validation.guide.specialty.size}")
        String specialtyTitle,

        @NotBlank(message = "{validation.guide.biography.notBlank}")
        @Size(min = 20, max = 1000, message = "{validation.guide.biography.size}")
        String biography,

        @NotNull(message = "{validation.guide.languages.notNull}")
        List<@NotBlank @Pattern(
                regexp = "^[A-Za-z]{2,3}$",
                message = "{validation.guide.language.invalid}"
        ) String> languageCodes,

        UUID avatarMediaId
) {

    public UpdateGuideProfileRequest {
        specialtyTitle = specialtyTitle == null ? null : specialtyTitle.trim();
        biography = biography == null ? null : biography.trim();
        languageCodes = languageCodes == null
                ? null
                : languageCodes.stream()
                        .map(code -> code == null ? null : code.trim())
                        .toList();
    }
}
