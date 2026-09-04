package com.pranav.jwtauth.provider;

import com.pranav.jwtauth.aws.PublicKeyProvider;
import com.pranav.jwtauth.config.JwtProperties;
import com.pranav.jwtauth.exception.AuthzFailureReason;
import com.pranav.jwtauth.exception.JwtValidationException;
import com.pranav.jwtauth.model.AuthenticatedUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SecurityException;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;

import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Parses and validates RS256-signed JWT access tokens issued by the {@code auth-service}.
 *
 * <p>This provider is validation-only: it never issues or signs tokens (token generation lives
 * exclusively in {@code auth-service}).
 */
@Slf4j
public class JwtTokenProvider {

    private static final String CLAIM_USERNAME = "username";
    private static final String CLAIM_USER_TYPE = "userType";
    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_PERMISSIONS = "permissions";
    private static final String CLAIM_REGION = "region";
    private static final String CLAIM_ZONE = "zone";

    private final PublicKeyProvider publicKeyProvider;
    private final JwtProperties properties;

    public JwtTokenProvider(PublicKeyProvider publicKeyProvider, JwtProperties properties) {
        this.publicKeyProvider = publicKeyProvider;
        this.properties = properties;
    }

    /**
     * Validates the given compact JWT (signature, expiry, not-before, issuer) and returns the
     * decoded principal.
     *
     * @throws JwtValidationException if the token is missing, malformed, expired, or has an
     *                                 invalid signature.
     */
    public AuthenticatedUser parseAndValidate(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new JwtValidationException(AuthzFailureReason.MISSING_TOKEN, "JWT token is missing");
        }

        Claims claims = parseClaims(rawToken);
        validateIssuer(claims);

        return AuthenticatedUser.builder()
                .userId(parseUserId(claims))
                .username(claims.get(CLAIM_USERNAME, String.class))
                .userType(claims.get(CLAIM_USER_TYPE, String.class))
                .roles(toStringSet(claims.get(CLAIM_ROLES, List.class)))
                .permissions(toStringSet(claims.get(CLAIM_PERMISSIONS, List.class)))
                .regionCode(claims.get(CLAIM_REGION, String.class))
                .zoneCode(claims.get(CLAIM_ZONE, String.class))
                .tokenId(claims.getId())
                .rawToken(rawToken)
                .build();
    }

    private Claims parseClaims(String rawToken) {
        RSAPublicKey key = publicKeyProvider.getPublicKey();
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .clockSkewSeconds(properties.getClockSkewSeconds())
                    .build()
                    .parseSignedClaims(rawToken)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new JwtValidationException(AuthzFailureReason.EXPIRED_TOKEN, "JWT token has expired", e);
        } catch (SignatureException e) {
            // Signature mismatch could mean the cached public key rotated; force a refresh for next call.
            publicKeyProvider.invalidate();
            throw new JwtValidationException(AuthzFailureReason.INVALID_SIGNATURE, "JWT signature validation failed", e);
        } catch (MalformedJwtException e) {
            throw new JwtValidationException(AuthzFailureReason.MALFORMED_TOKEN, "JWT token is malformed", e);
        } catch (UnsupportedJwtException | SecurityException e) {
            throw new JwtValidationException(AuthzFailureReason.INVALID_TOKEN, "JWT token is unsupported or invalid", e);
        } catch (IllegalArgumentException e) {
            throw new JwtValidationException(AuthzFailureReason.MALFORMED_TOKEN, "JWT token is empty or malformed", e);
        }
    }

    private void validateIssuer(Claims claims) {
        String expectedIssuer = properties.getIssuer();
        if (expectedIssuer == null || expectedIssuer.isBlank()) {
            return;
        }
        if (!expectedIssuer.equals(claims.getIssuer())) {
            throw new JwtValidationException(AuthzFailureReason.INVALID_TOKEN,
                    "JWT issuer '" + claims.getIssuer() + "' does not match expected issuer");
        }
    }

    private Long parseUserId(Claims claims) {
        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new JwtValidationException(AuthzFailureReason.INVALID_TOKEN, "JWT is missing a subject (user id) claim");
        }
        try {
            return Long.parseLong(subject);
        } catch (NumberFormatException e) {
            throw new JwtValidationException(AuthzFailureReason.INVALID_TOKEN, "JWT subject claim is not a valid user id", e);
        }
    }

    @SuppressWarnings("unchecked")
    private Set<String> toStringSet(List<?> rawList) {
        if (rawList == null || rawList.isEmpty()) {
            return Collections.emptySet();
        }
        return Set.copyOf((Collection<String>) (Collection<?>) rawList);
    }
}
