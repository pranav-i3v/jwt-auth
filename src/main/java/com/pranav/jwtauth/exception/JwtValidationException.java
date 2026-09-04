package com.pranav.jwtauth.exception;

import com.pranav.jwtauth.security.filter.JwtAuthenticationFilter;

/**
 * Thrown when a JWT fails structural/signature/expiry validation.
 * Always results in an HTTP 401 response from {@link JwtAuthenticationFilter}.
 */
public class JwtValidationException extends RuntimeException {

    private final AuthzFailureReason reason;

    public JwtValidationException(AuthzFailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public JwtValidationException(AuthzFailureReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public AuthzFailureReason getReason() {
        return reason;
    }
}
