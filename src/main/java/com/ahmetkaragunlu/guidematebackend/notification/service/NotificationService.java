package com.ahmetkaragunlu.guidematebackend.notification.service;

import com.ahmetkaragunlu.guidematebackend.common.dto.PageResponse;
import com.ahmetkaragunlu.guidematebackend.common.dto.UnreadCountResponse;
import com.ahmetkaragunlu.guidematebackend.common.exception.BusinessException;
import com.ahmetkaragunlu.guidematebackend.common.exception.ErrorCode;
import com.ahmetkaragunlu.guidematebackend.notification.domain.Notification;
import com.ahmetkaragunlu.guidematebackend.notification.domain.NotificationPushStatus;
import com.ahmetkaragunlu.guidematebackend.notification.dto.NotificationResponse;
import com.ahmetkaragunlu.guidematebackend.notification.dto.MarkRelatedNotificationsReadRequest;
import com.ahmetkaragunlu.guidematebackend.notification.repository.NotificationRepository;
import com.ahmetkaragunlu.guidematebackend.user.domain.User;
import com.ahmetkaragunlu.guidematebackend.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class NotificationService implements NotificationPublisher {

    private final NotificationRepository notificationRepository;
    private final NotificationPreferenceService preferenceService;
    private final NotificationPayloadCodec payloadCodec;
    private final UserRepository userRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final Clock clock;

    @Override
    @Transactional
    public UUID publish(NotificationCommand command) {
        if (command.deduplicationKey() != null) {
            Notification existing = notificationRepository
                    .findByRecipient_IdAndTypeAndDeduplicationKey(
                            command.recipientId(),
                            command.type(),
                            command.deduplicationKey()
                    )
                    .orElse(null);
            if (existing != null) {
                return existing.getId();
            }
        }
        NotificationPushStatus pushStatus = preferenceService.isPushEnabled(
                command.recipientId(),
                command.type()
        ) ? NotificationPushStatus.PENDING : NotificationPushStatus.NOT_REQUESTED;
        User recipient = userRepository.getReferenceById(command.recipientId());
        Notification notification = notificationRepository.save(new Notification(
                recipient,
                command.type(),
                command.actorId() == null ? null : userRepository.getReferenceById(command.actorId()),
                payloadCodec.encode(command.payload()),
                pushStatus,
                command.deduplicationKey()
        ));
        eventPublisher.publishEvent(new NotificationCreatedEvent(
                notification.getId(),
                recipient.getUsername(),
                pushStatus == NotificationPushStatus.PENDING
        ));
        return notification.getId();
    }

    @Transactional(readOnly = true)
    public PageResponse<NotificationResponse> getNotifications(User currentUser, int page, int size) {
        Page<NotificationResponse> notifications = notificationRepository
                .findByRecipient_IdOrderByCreatedAtDescIdDesc(
                        currentUser.getId(),
                        PageRequest.of(page, size)
                )
                .map(this::toResponse);
        return PageResponse.from(notifications);
    }

    @Transactional(readOnly = true)
    public UnreadCountResponse unreadCount(User currentUser) {
        return new UnreadCountResponse(
                notificationRepository.countByRecipient_IdAndReadAtIsNull(currentUser.getId())
        );
    }

    @Transactional
    public NotificationResponse markRead(User currentUser, UUID notificationId) {
        Notification notification = notificationRepository.findOwnedByIdForUpdate(
                        notificationId,
                        currentUser.getId()
                )
                .orElseThrow(() -> new BusinessException(ErrorCode.NOTIFICATION_NOT_FOUND));
        notification.markRead(clock.instant());
        return toResponse(notification);
    }

    @Transactional
    public UnreadCountResponse markAllRead(User currentUser) {
        notificationRepository.markAllRead(currentUser.getId(), clock.instant());
        return new UnreadCountResponse(0);
    }

    @Transactional
    public UnreadCountResponse markRelatedRead(
            User currentUser,
            MarkRelatedNotificationsReadRequest request
    ) {
        notificationRepository.markRelatedRead(
                currentUser.getId(),
                request.targetType().payloadKey(),
                request.targetId().toString(),
                clock.instant()
        );
        return unreadCount(currentUser);
    }

    private NotificationResponse toResponse(Notification notification) {
        return new NotificationResponse(
                notification.getId(),
                notification.getType(),
                notification.getActor() == null ? null : notification.getActor().getId(),
                notification.getActor() == null ? null : notification.getActor().displayName(),
                payloadCodec.decode(notification.getPayloadJson()),
                notification.isRead(),
                notification.getReadAt(),
                notification.getCreatedAt()
        );
    }
}
