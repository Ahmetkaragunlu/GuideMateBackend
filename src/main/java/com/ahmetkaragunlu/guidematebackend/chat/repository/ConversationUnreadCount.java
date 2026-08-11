package com.ahmetkaragunlu.guidematebackend.chat.repository;

import java.util.UUID;

public interface ConversationUnreadCount {

    UUID getConversationId();

    long getUnreadCount();
}
