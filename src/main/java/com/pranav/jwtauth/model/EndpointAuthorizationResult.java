package com.pranav.jwtauth.model;

import lombok.Builder;
import lombok.Getter;

/**
 * Result of an endpoint authorization check performed via the
 * {@code sp_check_endpoint_authorization} stored procedure.
 */
@Getter
@Builder
public class EndpointAuthorizationResult {

    private final boolean allowed;

    private final boolean mfaRequired;

    private final boolean rateLimited;

    private final String reasonCode;

    private final String message;

    public static EndpointAuthorizationResult allow() {
        return EndpointAuthorizationResult.builder().allowed(true).build();
    }

    public static EndpointAuthorizationResult deny(String reasonCode, String message) {
        return EndpointAuthorizationResult.builder()
                .allowed(false)
                .reasonCode(reasonCode)
                .message(message)
                .build();
    }
}
