package com.ahmetkaragunlu.guidematebackend.profile.domain;

import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.MapsId;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;
import org.hibernate.annotations.BatchSize;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

@Getter
@Entity
@Table(name = "guide_profiles")
@EntityListeners(AuditingEntityListener.class)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class GuideProfile {

    @Id
    @Column(name = "user_id")
    private Long userId;

    @MapsId
    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "specialty_title", nullable = false, length = 60)
    private String specialtyTitle;

    @Column(name = "biography", nullable = false, length = 1000)
    private String biography;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "guide_languages", joinColumns = @JoinColumn(name = "guide_id"))
    @Column(name = "language_code", nullable = false, length = 3)
    @BatchSize(size = 50)
    private Set<String> languageCodes = new LinkedHashSet<>();

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    private GuideProfile(
            User user,
            String specialtyTitle,
            String biography,
            Collection<String> languageCodes
    ) {
        this.user = Objects.requireNonNull(user);
        updateDetails(specialtyTitle, biography, languageCodes);
    }

    public static GuideProfile create(
            User user,
            String specialtyTitle,
            String biography,
            Collection<String> languageCodes
    ) {
        return new GuideProfile(user, specialtyTitle, biography, languageCodes);
    }

    public void updateDetails(
            String specialtyTitle,
            String biography,
            Collection<String> languageCodes
    ) {
        this.specialtyTitle = Objects.requireNonNull(specialtyTitle);
        this.biography = Objects.requireNonNull(biography);
        this.languageCodes.clear();
        this.languageCodes.addAll(Objects.requireNonNull(languageCodes));
    }

}
