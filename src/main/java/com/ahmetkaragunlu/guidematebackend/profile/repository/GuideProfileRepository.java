package com.ahmetkaragunlu.guidematebackend.profile.repository;

import com.ahmetkaragunlu.guidematebackend.profile.domain.GuideProfile;
import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Repository
public interface GuideProfileRepository extends JpaRepository<GuideProfile, Long> {

    @EntityGraph(attributePaths = {"user", "user.role", "avatar", "languageCodes"})
    Optional<GuideProfile> findByUserId(Long userId);

    @EntityGraph(attributePaths = {"user", "user.role", "avatar", "languageCodes"})
    @Query("SELECT profile FROM GuideProfile profile WHERE profile.userId IN :userIds")
    List<GuideProfile> findAllByUserIdIn(@Param("userIds") Collection<Long> userIds);

    @EntityGraph(attributePaths = {"user", "user.role", "avatar"})
    @Query(
            value = """
                    SELECT profile
                    FROM GuideProfile profile
                    JOIN profile.user user
                    JOIN user.role role
                    WHERE user.accountStatus = :accountStatus
                      AND role.name = :roleName
                      AND (
                          LOWER(user.firstName) LIKE LOWER(CONCAT('%', :query, '%'))
                          OR LOWER(user.lastName) LIKE LOWER(CONCAT('%', :query, '%'))
                          OR LOWER(CONCAT(user.firstName, CONCAT(' ', user.lastName))) LIKE LOWER(CONCAT('%', :query, '%'))
                          OR LOWER(profile.specialtyTitle) LIKE LOWER(CONCAT('%', :query, '%'))
                      )
                    """,
            countQuery = """
                    SELECT COUNT(profile)
                    FROM GuideProfile profile
                    JOIN profile.user user
                    JOIN user.role role
                    WHERE user.accountStatus = :accountStatus
                      AND role.name = :roleName
                      AND (
                          LOWER(user.firstName) LIKE LOWER(CONCAT('%', :query, '%'))
                          OR LOWER(user.lastName) LIKE LOWER(CONCAT('%', :query, '%'))
                          OR LOWER(CONCAT(user.firstName, CONCAT(' ', user.lastName))) LIKE LOWER(CONCAT('%', :query, '%'))
                          OR LOWER(profile.specialtyTitle) LIKE LOWER(CONCAT('%', :query, '%'))
                      )
                    """
    )
    Page<GuideProfile> searchPublicProfiles(
            @Param("query") String query,
            @Param("accountStatus") AccountStatus accountStatus,
            @Param("roleName") String roleName,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"user", "user.role", "avatar"})
    @Query(
            value = """
                    SELECT profile
                    FROM GuideProfile profile
                    JOIN profile.user user
                    JOIN user.role role
                    WHERE user.accountStatus = :accountStatus
                      AND role.name = :roleName
                    """,
            countQuery = """
                    SELECT COUNT(profile)
                    FROM GuideProfile profile
                    JOIN profile.user user
                    JOIN user.role role
                    WHERE user.accountStatus = :accountStatus
                      AND role.name = :roleName
                    """
    )
    Page<GuideProfile> findPublicProfiles(
            @Param("accountStatus") AccountStatus accountStatus,
            @Param("roleName") String roleName,
            Pageable pageable
    );

    @EntityGraph(attributePaths = {"user", "user.role", "avatar", "languageCodes"})
    @Query("""
            SELECT profile
            FROM GuideProfile profile
            JOIN profile.user user
            JOIN user.role role
            WHERE user.accountStatus = :accountStatus
              AND role.name = :roleName
            """)
    List<GuideProfile> findAllPublicProfiles(
            @Param("accountStatus") AccountStatus accountStatus,
            @Param("roleName") String roleName
    );

    boolean existsByAvatar_Id(UUID mediaAssetId);

    @Query("""
            SELECT CASE WHEN COUNT(profile) > 0 THEN true ELSE false END
            FROM GuideProfile profile
            JOIN profile.user user
            JOIN user.role role
            WHERE profile.avatar.id = :mediaAssetId
              AND user.accountStatus = :accountStatus
              AND role.name = :roleName
            """)
    boolean existsPublicAvatarReference(
            @Param("mediaAssetId") UUID mediaAssetId,
            @Param("accountStatus") AccountStatus accountStatus,
            @Param("roleName") String roleName
    );
}
