package com.ahmetkaragunlu.guidematebackend.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    USER_NOT_FOUND("error.user.notFound", HttpStatus.NOT_FOUND),
    EMAIL_ALREADY_EXISTS("error.email.alreadyExists", HttpStatus.CONFLICT),
    ACCOUNT_PENDING_VERIFICATION("error.account.pendingVerification", HttpStatus.FORBIDDEN),
    ACCOUNT_DISABLED("error.account.disabled", HttpStatus.FORBIDDEN),
    INVALID_CREDENTIALS("error.credentials.invalid", HttpStatus.UNAUTHORIZED),
    CURRENT_PASSWORD_INCORRECT("error.password.currentIncorrect", HttpStatus.BAD_REQUEST),
    PASSWORD_POLICY_VIOLATION("error.password.policy", HttpStatus.BAD_REQUEST),
    PASSWORD_SAME_AS_CURRENT("error.password.sameAsCurrent", HttpStatus.BAD_REQUEST),
    PASSWORDS_DO_NOT_MATCH("error.passwords.notMatch", HttpStatus.BAD_REQUEST),
    ROLE_ALREADY_SELECTED("error.role.alreadySelected", HttpStatus.CONFLICT),
    ROLE_NOT_FOUND("error.role.notFound", HttpStatus.NOT_FOUND),
    INVALID_INSTALLATION_ID("error.installation.invalid", HttpStatus.BAD_REQUEST),

    GUIDE_PROFILE_NOT_FOUND("error.guideProfile.notFound", HttpStatus.NOT_FOUND),
    INVALID_LANGUAGE_CODE("error.language.invalid", HttpStatus.BAD_REQUEST),

    MEDIA_NOT_FOUND("error.media.notFound", HttpStatus.NOT_FOUND),
    MEDIA_INVALID_TYPE("error.media.invalidType", HttpStatus.BAD_REQUEST),
    MEDIA_TOO_LARGE("error.media.tooLarge", HttpStatus.PAYLOAD_TOO_LARGE),
    MEDIA_STORAGE_FAILED("error.media.storageFailed", HttpStatus.SERVICE_UNAVAILABLE),
    MEDIA_IN_USE("error.media.inUse", HttpStatus.CONFLICT),
    MEDIA_PURPOSE_MISMATCH("error.media.purposeMismatch", HttpStatus.BAD_REQUEST),

    TOUR_NOT_FOUND("error.tour.notFound", HttpStatus.NOT_FOUND),
    TOUR_NOT_APPROVED("error.tour.notApproved", HttpStatus.CONFLICT),
    TOUR_CHANGE_PENDING("error.tour.changePending", HttpStatus.CONFLICT),
    TOUR_LOCATION_LOCKED("error.tour.locationLocked", HttpStatus.CONFLICT),
    TOUR_NOT_ARCHIVABLE("error.tour.notArchivable", HttpStatus.CONFLICT),
    TOUR_REVIEW_NOT_FOUND("error.tourReview.notFound", HttpStatus.NOT_FOUND),
    TOUR_REVIEW_STATE_INVALID("error.tourReview.stateInvalid", HttpStatus.CONFLICT),
    INVALID_CATEGORY_CODE("error.tour.categoryInvalid", HttpStatus.BAD_REQUEST),
    INVALID_COUNTRY_CODE("error.tour.countryInvalid", HttpStatus.BAD_REQUEST),
    INVALID_TIME_ZONE("error.tour.timeZoneInvalid", HttpStatus.BAD_REQUEST),
    SESSION_NOT_FOUND("error.tourSession.notFound", HttpStatus.NOT_FOUND),
    SESSION_NOT_BOOKABLE("error.tourSession.notBookable", HttpStatus.CONFLICT),
    SESSION_ALREADY_STARTED("error.tourSession.alreadyStarted", HttpStatus.CONFLICT),
    SESSION_HAS_RESERVATIONS("error.tourSession.hasReservations", HttpStatus.CONFLICT),
    CAPACITY_NOT_AVAILABLE("error.tourSession.capacityNotAvailable", HttpStatus.CONFLICT),
    CAPACITY_BELOW_BOOKED_COUNT("error.tourSession.capacityBelowBooked", HttpStatus.CONFLICT),
    SESSION_STATUS_NOT_MANAGEABLE("error.tourSession.statusNotManageable", HttpStatus.CONFLICT),
    SCHEDULE_CONFLICT("error.tourSession.scheduleConflict", HttpStatus.CONFLICT),
    CONCURRENT_UPDATE("error.concurrentUpdate", HttpStatus.CONFLICT),

    RESERVATION_NOT_FOUND("error.reservation.notFound", HttpStatus.NOT_FOUND),
    RESERVATION_ALREADY_EXISTS("error.reservation.alreadyExists", HttpStatus.CONFLICT),
    RESERVATION_NOT_CANCELLABLE("error.reservation.notCancellable", HttpStatus.CONFLICT),
    INVALID_PARTICIPANT_COUNT("error.reservation.participantCountInvalid", HttpStatus.BAD_REQUEST),
    REVIEW_NOT_ALLOWED("error.review.notAllowed", HttpStatus.CONFLICT),
    REVIEW_ALREADY_EXISTS("error.review.alreadyExists", HttpStatus.CONFLICT),
    IDEMPOTENCY_CONFLICT("error.idempotency.conflict", HttpStatus.CONFLICT),

    PAYMENT_NOT_FOUND("error.payment.notFound", HttpStatus.NOT_FOUND),
    PAYMENT_INITIALIZATION_FAILED("error.payment.initializationFailed", HttpStatus.SERVICE_UNAVAILABLE),
    PAYMENT_VERIFICATION_FAILED("error.payment.verificationFailed", HttpStatus.BAD_REQUEST),
    PAYMENT_NOT_CANCELLABLE("error.payment.notCancellable", HttpStatus.CONFLICT),
    PAYMENT_CURRENCY_NOT_SUPPORTED("error.payment.currencyNotSupported", HttpStatus.BAD_REQUEST),
    FX_QUOTE_UNAVAILABLE("error.payment.fxQuoteUnavailable", HttpStatus.SERVICE_UNAVAILABLE),
    FX_QUOTE_EXPIRED("error.payment.fxQuoteExpired", HttpStatus.CONFLICT),
    CARD_INSUFFICIENT_FUNDS("error.payment.cardInsufficientFunds", HttpStatus.PAYMENT_REQUIRED),
    PAYMENT_METHOD_DECLINED("error.payment.methodDeclined", HttpStatus.PAYMENT_REQUIRED),
    SAVED_CARD_NOT_FOUND("error.savedCard.notFound", HttpStatus.NOT_FOUND),
    SAVED_CARD_SYNC_FAILED("error.savedCard.syncFailed", HttpStatus.CONFLICT),
    SAVED_CARD_PROVIDER_UNAVAILABLE("error.savedCard.providerUnavailable", HttpStatus.SERVICE_UNAVAILABLE),
    INVALID_AMOUNT("error.payment.invalidAmount", HttpStatus.BAD_REQUEST),
    REFUND_FAILED("error.refund.failed", HttpStatus.CONFLICT),
    REFUND_AMOUNT_EXCEEDED("error.refund.amountExceeded", HttpStatus.CONFLICT),
    INSUFFICIENT_WALLET_BALANCE("error.wallet.insufficientBalance", HttpStatus.CONFLICT),
    INSUFFICIENT_WITHDRAWABLE_BALANCE("error.wallet.insufficientWithdrawableBalance", HttpStatus.CONFLICT),
    BANK_ACCOUNT_NOT_FOUND("error.bankAccount.notFound", HttpStatus.NOT_FOUND),
    BANK_ACCOUNT_INVALID("error.bankAccount.invalid", HttpStatus.BAD_REQUEST),
    BANK_ACCOUNT_ALREADY_EXISTS("error.bankAccount.alreadyExists", HttpStatus.CONFLICT),

    NOTIFICATION_NOT_FOUND("error.notification.notFound", HttpStatus.NOT_FOUND),
    CHAT_NOT_FOUND("error.chat.notFound", HttpStatus.NOT_FOUND),
    CHAT_PARTICIPANT_INVALID("error.chat.participantInvalid", HttpStatus.BAD_REQUEST),
    CHAT_MESSAGE_NOT_FOUND("error.chat.messageNotFound", HttpStatus.NOT_FOUND),
    CHAT_MESSAGE_TOO_LONG("error.chat.messageTooLong", HttpStatus.BAD_REQUEST),

    INVALID_TOKEN("error.token.invalid", HttpStatus.BAD_REQUEST),
    TOKEN_EXPIRED("error.token.expired", HttpStatus.BAD_REQUEST),
    TOKEN_ALREADY_USED("error.token.alreadyUsed", HttpStatus.BAD_REQUEST),
    INVALID_REFRESH_TOKEN("error.refreshToken.invalid", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_EXPIRED("error.refreshToken.expired", HttpStatus.UNAUTHORIZED),
    REFRESH_TOKEN_REPLAY("error.refreshToken.replay", HttpStatus.UNAUTHORIZED),

    GOOGLE_LOGIN_FAILED("error.google.loginFailed", HttpStatus.UNAUTHORIZED),
    GOOGLE_ACCOUNT_NOT_FOUND("error.google.accountNotFound", HttpStatus.NOT_FOUND),
    GOOGLE_ACCOUNT_MISMATCH("error.google.accountMismatch", HttpStatus.CONFLICT),

    UNAUTHORIZED("error.security.unauthorized", HttpStatus.UNAUTHORIZED),
    FORBIDDEN("error.security.forbidden", HttpStatus.FORBIDDEN),
    VALIDATION_FAILED("error.validation.failed", HttpStatus.BAD_REQUEST),
    MALFORMED_REQUEST("error.request.malformed", HttpStatus.BAD_REQUEST),
    DATA_CONFLICT("error.data.conflict", HttpStatus.CONFLICT),
    RATE_LIMITED("error.rateLimit.exceeded", HttpStatus.TOO_MANY_REQUESTS),
    EMAIL_DELIVERY_FAILED("error.email.deliveryFailed", HttpStatus.SERVICE_UNAVAILABLE),
    INTERNAL_SERVER_ERROR("error.server.internal", HttpStatus.INTERNAL_SERVER_ERROR);

    private final String messageKey;
    private final HttpStatus httpStatus;

    ErrorCode(String messageKey, HttpStatus httpStatus) {
        this.messageKey = messageKey;
        this.httpStatus = httpStatus;
    }
}
