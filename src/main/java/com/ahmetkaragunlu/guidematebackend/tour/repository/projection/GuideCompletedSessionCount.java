package com.ahmetkaragunlu.guidematebackend.tour.repository.projection;

public interface GuideCompletedSessionCount {

    Long getGuideId();

    long getCompletedSessionCount();
}
