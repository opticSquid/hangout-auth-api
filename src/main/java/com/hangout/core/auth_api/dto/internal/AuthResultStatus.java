package com.hangout.core.auth_api.dto.internal;

public enum AuthResultStatus {
    LONG_TERM_ACCESS("long term access"),
    SHORT_TERM_ACCESS("short term access"),
    USER_BLOCKED("user blocked"),
    USER_NOT_ENABLED("user not verified");

    public final String label;

    private AuthResultStatus(String label) {
        this.label = label;
    }
}
