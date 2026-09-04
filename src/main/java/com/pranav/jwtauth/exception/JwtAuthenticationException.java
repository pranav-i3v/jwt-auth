package com.pranav.jwtauth.exception;

import org.springframework.security.core.AuthenticationException;
import org.springframework.http.HttpStatus;

/**
 * An authentication failure produced while validating a bearer JWT.
 *
 * <p>The reason is retained so the HTTP layer can preserve this library's error response
 * contract while the authentication itself is delegated through Spring Security.
 */
public class JwtAuthenticationException extends AuthenticationException {

    private final AuthzFailureReason reason;
    private final HttpStatus status;

    public JwtAuthenticationException(AuthzFailureReason reason, String message, Throwable cause) {
        this(reason, HttpStatus.UNAUTHORIZED, message, cause);
    }

    public JwtAuthenticationException(AuthzFailureReason reason, HttpStatus status, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
        this.status = status;
    }

    public AuthzFailureReason getReason() {
        return reason;
    }

    public HttpStatus getStatus() {
        return status;
    }
}
