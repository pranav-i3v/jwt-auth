package com.pranav.jwtauth.exception;

/**
 * Reason codes surfaced to clients / logs when a request is rejected by the authz-starter filter.
 * Mirrors the {@code access_status} enum used in the {@code endpoint_access_log} table.
 */
public enum AuthzFailureReason {
    MISSING_TOKEN,
    MALFORMED_TOKEN,
    EXPIRED_TOKEN,
    INVALID_SIGNATURE,
    INVALID_TOKEN,
    TOKEN_BLACKLISTED,
    DENIED_NO_PERMISSION,
    DENIED_MFA,
    DENIED_RATE_LIMIT,
    ERROR
}
