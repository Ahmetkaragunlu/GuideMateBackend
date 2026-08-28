package com.ahmetkaragunlu.guidematebackend.user.repository;

import com.ahmetkaragunlu.guidematebackend.user.domain.AccountStatus;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<User> findByGoogleSubject(String googleSubject);

    boolean existsByAvatarMediaId(UUID avatarMediaId);

    @Query("""
            SELECT CASE WHEN COUNT(user) > 0 THEN true ELSE false END
            FROM User user
            WHERE user.avatarMediaId = :mediaAssetId
              AND user.accountStatus = :accountStatus
            """)
    boolean existsActiveAvatarReference(
            @Param("mediaAssetId") UUID mediaAssetId,
            @Param("accountStatus") AccountStatus accountStatus
    );

    @Query("SELECT u FROM User u LEFT JOIN FETCH u.role WHERE u.email = :email")
    Optional<User> findByEmailWithRole(@Param("email") String email);

    @Query("SELECT u FROM User u LEFT JOIN FETCH u.role WHERE u.googleSubject = :googleSubject")
    Optional<User> findByGoogleSubjectWithRole(@Param("googleSubject") String googleSubject);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT u FROM User u WHERE u.email = :email")
    Optional<User> findByEmailForUpdate(@Param("email") String email);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("SELECT u FROM User u WHERE u.id = :id")
    Optional<User> findByIdForUpdate(@Param("id") Long id);
}
