package com.ahmetkaragunlu.guidematebackend.reservation.repository;

import java.util.UUID;

public interface SessionOccupancy {

    UUID getSessionId();

    long getParticipantCount();
}
