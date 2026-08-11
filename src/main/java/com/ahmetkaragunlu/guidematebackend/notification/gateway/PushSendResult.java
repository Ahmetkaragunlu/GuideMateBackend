package com.ahmetkaragunlu.guidematebackend.notification.gateway;

public record PushSendResult(boolean delivered, boolean registrationInvalid) {

    public static PushSendResult sent() {
        return new PushSendResult(true, false);
    }

    public static PushSendResult failed() {
        return new PushSendResult(false, false);
    }

    public static PushSendResult invalidRegistration() {
        return new PushSendResult(false, true);
    }
}
