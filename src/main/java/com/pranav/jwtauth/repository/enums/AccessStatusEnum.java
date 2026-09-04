package com.pranav.jwtauth.repository.enums;

public enum AccessStatusEnum {
    ALLOWED,
    INVALID_TOKEN,
    DENIED_NO_PERMISSION,
    DENIED_INACTIVE,
    DENIED_EXPIRED,
    DENIED_MFA,
    DENIED_RATE_LIMIT,
    ENDPOINT_NOT_FOUND,
    ERROR,
    RESOLVED
}
