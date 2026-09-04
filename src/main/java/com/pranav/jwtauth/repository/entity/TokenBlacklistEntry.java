package com.pranav.jwtauth.repository.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

/**
 * JPA mapping for the {@code token_blacklist} table: one row per revoked JWT id (jti).
 *
 * <p>Read-only from this library's point of view - rows are written by {@code auth-service} on
 * logout / forced revocation.
 */
@Entity
@Table(name = "token_blacklist")
@Getter
@Setter
@NoArgsConstructor
public class TokenBlacklistEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    /**
     * The revoked JWT's {@code jti} claim.
     */
    @Column(name = "token_jti", nullable = false)
    private String tokenJti;

    /**
     * Original token expiry; rows past this instant are ignored (the token is dead anyway).
     */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
