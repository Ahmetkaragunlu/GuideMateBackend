package com.ahmetkaragunlu.guidematebackend.notification.repository;

import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPreference;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface NotificationPreferenceRepository extends JpaRepository<NotificationPreference, Long> {
}
