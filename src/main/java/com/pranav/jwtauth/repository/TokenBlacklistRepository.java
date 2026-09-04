package com.pranav.jwtauth.repository;

import com.pranav.jwtauth.repository.entity.TokenBlacklistEntry;
import org.springframework.data.repository.Repository;

import java.time.Instant;

/**
 * Spring Data JPA repository over {@code token_blacklist}.
 *
 * <p>Extends the bare {@link Repository} marker rather than {@code JpaRepository} on purpose: this
 * bean is exported into every consuming microservice's context, so it exposes the single read the
 * library needs and no mutating CRUD methods over a security-critical table.
 */
public interface TokenBlacklistRepository extends Repository<TokenBlacklistEntry, Long> {

    /**
     * Returns {@code true} if the given JWT id (jti) has been revoked and that revocation has not
     * yet aged out.
     *
     * @param tokenJti the JWT {@code jti} claim
     * @param now      cut-off instant; entries expiring at or before this are ignored
     */
    boolean existsByTokenJtiAndExpiresAtAfter(String tokenJti, Instant now);
}
