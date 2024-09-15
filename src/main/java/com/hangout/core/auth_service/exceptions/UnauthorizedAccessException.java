package com.hangout.core.auth_service.exceptions;

public class UnauthorizedAccessException extends RuntimeException {
    private String message;

    public UnauthorizedAccessException() {
        super();
    }

    public UnauthorizedAccessException(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}