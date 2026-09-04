package com.pranav.jwtauth.model;

import com.pranav.jwtauth.security.filter.JwtAuthenticationFilter;
import lombok.Builder;
import lombok.Getter;
import lombok.ToString;

import java.util.Set;

/**
 * Immutable representation of the authenticated principal, populated from validated JWT claims.
 * Set as the {@link org.springframework.security.core.Authentication} principal after successful
 * token validation in {@link JwtAuthenticationFilter}.
 */
@Getter
@Builder
@ToString
public class AuthenticatedUser {

    /** Maps to the {@code sub} claim / users.id */
    private final Long userId;

    private final String username;

    private final String userType;

    /** Role names granted to the user (e.g. "SUPPORT_STAFF", "ADMIN"). */
    private final Set<String> roles;

    /** Fine-grained permission codes (e.g. "bills:read"). */
    private final Set<String> permissions;

    private final String regionCode;

    private final String zoneCode;

    /** JWT ID claim ({@code jti}) - used for blacklist checks. */
    private final String tokenId;

    /** Raw compact JWT, kept for downstream propagation to other services if needed. */
    private final String rawToken;
}
