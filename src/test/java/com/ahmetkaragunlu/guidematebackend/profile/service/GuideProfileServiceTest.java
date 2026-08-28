package com.ahmetkaragunlu.guidematebackend.profile.service;

import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.common.validation.LanguageCodePolicy;
import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuidePerformanceSummary;
import com.ahmetkaragunlu.guidematebackend.profile.dto.GuideProfileResponse;
import com.ahmetkaragunlu.guidematebackend.profile.dto.UpdateGuideProfileRequest;
import com.ahmetkaragunlu.guidematebackend.profile.mapper.GuideProfileMapper;
import com.ahmetkaragunlu.guidematebackend.profile.repository.GuideProfileRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.RoleType;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GuideProfileServiceTest {

    @Mock
    private GuideProfileRepository guideProfileRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private GuideProfileMapper guideProfileMapper;
    @Mock
    private GuidePerformanceService guidePerformanceService;

    private GuideProfileService service;

    @BeforeEach
    void setUp() {
        service = new GuideProfileService(
                guideProfileRepository,
                userRepository,
                guideProfileMapper,
                new LanguageCodePolicy(),
                guidePerformanceService
        );
    }

    @Test
    void createsProfileWithNormalizedLanguages() {
        User currentUser = org.mockito.Mockito.mock(User.class);
        User reference = org.mockito.Mockito.mock(User.class);
        GuidePerformanceSummary performance = org.mockito.Mockito.mock(GuidePerformanceSummary.class);
        GuideProfileResponse expected = org.mockito.Mockito.mock(GuideProfileResponse.class);
        when(currentUser.getId()).thenReturn(42L);
        when(guideProfileRepository.findByUserId(42L)).thenReturn(Optional.empty());
        when(userRepository.getReferenceById(42L)).thenReturn(reference);
        when(guideProfileRepository.save(org.mockito.ArgumentMatchers.any(GuideProfile.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(guidePerformanceService.get(42L)).thenReturn(performance);
        when(guideProfileMapper.toResponse(
                org.mockito.ArgumentMatchers.eq(currentUser),
                org.mockito.ArgumentMatchers.any(GuideProfile.class),
                org.mockito.ArgumentMatchers.eq(performance)
        )).thenReturn(expected);

        GuideProfileResponse result = service.updateProfile(
                currentUser,
                new UpdateGuideProfileRequest(
                        "  History Guide  ",
                        "  A sufficiently detailed professional guide biography.  ",
                        List.of("EN", " tr ", "en")
                )
        );

        assertThat(result).isSameAs(expected);
        ArgumentCaptor<GuideProfile> profileCaptor = ArgumentCaptor.forClass(GuideProfile.class);
        verify(guideProfileRepository).save(profileCaptor.capture());
        assertThat(profileCaptor.getValue().getSpecialtyTitle()).isEqualTo("History Guide");
        assertThat(profileCaptor.getValue().getBiography())
                .isEqualTo("A sufficiently detailed professional guide biography.");
        assertThat(profileCaptor.getValue().getLanguageCodes()).containsExactly("en", "tr");
    }

    @Test
    void hidesDisabledGuideProfileAsNotFound() {
        User disabledGuide = org.mockito.Mockito.mock(User.class);
        GuideProfile profile = org.mockito.Mockito.mock(GuideProfile.class);
        when(guideProfileRepository.findByUserId(7L)).thenReturn(Optional.of(profile));
        when(profile.getUser()).thenReturn(disabledGuide);
        when(disabledGuide.getAccountStatus()).thenReturn(AccountStatus.DISABLED);

        assertThatThrownBy(() -> service.getPublicProfile(7L))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.GUIDE_PROFILE_NOT_FOUND));
    }

    @Test
    void hidesActiveNonGuideProfileAsNotFound() {
        User tourist = org.mockito.Mockito.mock(User.class);
        GuideProfile profile = org.mockito.Mockito.mock(GuideProfile.class);
        when(guideProfileRepository.findByUserId(7L)).thenReturn(Optional.of(profile));
        when(profile.getUser()).thenReturn(tourist);
        when(tourist.getAccountStatus()).thenReturn(AccountStatus.ACTIVE);
        when(tourist.hasRole(RoleType.ROLE_GUIDE)).thenReturn(false);

        assertThatThrownBy(() -> service.getPublicProfile(7L))
                .isInstanceOfSatisfying(BusinessException.class, exception ->
                        assertThat(exception.getErrorCode()).isEqualTo(ErrorCode.GUIDE_PROFILE_NOT_FOUND));
    }
}
