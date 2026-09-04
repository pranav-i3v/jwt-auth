package com.pranav.jwtauth.refresh;

/** Indicates whether a refresh failure was a rejected token or an unavailable auth service. */
public class RefreshTokenClientException extends RuntimeException {

    private final boolean serviceUnavailable;

    private RefreshTokenClientException(String message, Throwable cause, boolean serviceUnavailable) {
        super(message, cause);
        this.serviceUnavailable = serviceUnavailable;
    }

    public static RefreshTokenClientException rejected(Throwable cause) {
        return new RefreshTokenClientException("Refresh token was rejected by the auth service", cause, false);
    }

    public static RefreshTokenClientException unavailable(Throwable cause) {
        return new RefreshTokenClientException("Auth service is unavailable for token refresh", cause, true);
    }

    public boolean isServiceUnavailable() {
        return serviceUnavailable;
    }
}
