package com.pranav.jwtauth.service;

import com.pranav.jwtauth.config.JwtProperties;
import com.pranav.jwtauth.model.AuthenticatedUser;
import com.pranav.jwtauth.model.EndpointAuthorizationResult;
import com.pranav.jwtauth.repository.EndpointAccessLogRepository;
import com.pranav.jwtauth.repository.EndpointAuthorizationRepository;
import com.pranav.jwtauth.repository.EndpointAuthorizationRow;
import com.pranav.jwtauth.repository.TokenBlacklistRepository;
import com.pranav.jwtauth.repository.entity.EndpointAccessLog;
import com.pranav.jwtauth.repository.enums.AccessStatusEnum;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;

/**
 * Authorization policy layer backing the authz-starter filter: blacklist checks, endpoint
 * authorization, and access logging.
 *
 * <p>Holds no SQL of its own - every database operation goes through a repository
 * ({@link TokenBlacklistRepository}, {@link EndpointAuthorizationRepository},
 * {@link EndpointAccessLogRepository}). What stays here is policy: the {@code authz.*} enable
 * flags, fail-closed blacklist behaviour, fail-open/fail-closed handling of authorization errors,
 * and the guarantee that access logging never breaks the request path.
 */
@Slf4j
public class AuthorizationService {

    private final TokenBlacklistRepository tokenBlacklistRepository;
    private final EndpointAuthorizationRepository endpointAuthorizationRepository;
    private final EndpointAccessLogRepository endpointAccessLogRepository;
    private final TransactionTemplate transactionTemplate;
    private final JwtProperties properties;

    public AuthorizationService(TokenBlacklistRepository tokenBlacklistRepository,
                                EndpointAuthorizationRepository endpointAuthorizationRepository,
                                EndpointAccessLogRepository endpointAccessLogRepository,
                                PlatformTransactionManager transactionManager,
                                JwtProperties properties) {
        this.tokenBlacklistRepository = tokenBlacklistRepository;
        this.endpointAuthorizationRepository = endpointAuthorizationRepository;
        this.endpointAccessLogRepository = endpointAccessLogRepository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
        this.properties = properties;
    }

    /**
     * Returns {@code true} if the given JWT id (jti) is present (and not yet expired) in the
     * {@code token_blacklist} table.
     */
    public boolean isTokenBlacklisted(String tokenId) {
        if (!properties.getBlacklist().isEnabled() || tokenId == null || tokenId.isBlank()) {
            return false;
        }
        try {
            return tokenBlacklistRepository.existsByTokenJtiAndExpiresAtAfter(tokenId, Instant.now());
        } catch (Exception e) {
            log.error("Failed to check token blacklist for jti={}; failing closed (treating as blacklisted)", tokenId, e);
            return true;
        }
    }

    /**
     * Invokes the {@code sp_check_endpoint_authorization} stored procedure to determine whether
     * the given user may access the given endpoint/method.
     */
    public EndpointAuthorizationResult checkEndpointAuthorization(AuthenticatedUser user, String endpointPath, String httpMethod) {
        if (!properties.getAuthorization().isEnabled()) {
            return EndpointAuthorizationResult.allow();
        }
        try {
            return endpointAuthorizationRepository.checkEndpointAuthorization(user.getUserId(), endpointPath, httpMethod)
                    .map(AuthorizationService::toResult)
                    .orElseGet(() -> EndpointAuthorizationResult.deny("NO_RESULT", "Authorization routine returned no result"));
        } catch (Exception e) {
            log.error("Endpoint authorization check failed for userId={}, endpoint={} {}",
                    user.getUserId(), httpMethod, endpointPath, e);
            if (properties.getAuthorization().isFailOpenOnError()) {
                return EndpointAuthorizationResult.allow();
            }
            return EndpointAuthorizationResult.deny("ERROR", "Authorization check failed");
        }
    }

    private static EndpointAuthorizationResult toResult(EndpointAuthorizationRow row) {
        return EndpointAuthorizationResult.builder()
                .allowed(row.isAllowed())
                .reasonCode(row.getReasonCode())
                .build();
    }

    /**
     * Persists an access-log entry. Runs asynchronously (fire-and-forget) when
     * {@code authz.access-log.async=true}, so it never adds latency to the request path.
     */
    @Async("authzAccessLogExecutor")
    public void logAccessAsync(AccessLogEntry entry) {
        logAccess(entry);
    }

    public void logAccess(AccessLogEntry entry) {
        if (!properties.getAccessLog().isEnabled()) {
            return;
        }
        try {
            // Demarcated here rather than on the repository: the commit has to happen inside this
            // try block, so that a failure to commit is swallowed like any other logging failure.
            transactionTemplate.executeWithoutResult(status -> endpointAccessLogRepository.save(toEntity(entry)));
        } catch (Exception e) {
            // Access logging must never break the request path.
            log.error("Failed to write endpoint_access_log entry: {}", entry, e);
        }
    }

    private static EndpointAccessLog toEntity(AccessLogEntry entry) {
        EndpointAccessLog accessLog = new EndpointAccessLog();
        accessLog.setUserId(entry.userId());
        accessLog.setUsername(entry.username());
        accessLog.setApiEndpointId(entry.apiEndpointId());
        accessLog.setEndpointPath(entry.endpointPath());
        accessLog.setHttpMethod(entry.httpMethod());
        accessLog.setRequestIp(entry.requestIp());
        accessLog.setUserAgent(entry.userAgent());
        accessLog.setDeviceId(entry.deviceId());
        accessLog.setAccessStatus(AccessStatusEnum.valueOf(entry.accessStatus()));
        accessLog.setResponseStatusCode(entry.responseStatusCode());
        accessLog.setResponseTimeMs(entry.responseTimeMs());
        accessLog.setAccessedAt(Instant.now());
        return accessLog;
    }

    /**
     * Immutable payload for an {@code endpoint_access_log} row.
     */
    public record AccessLogEntry(
            Long userId,
            String username,
            Long apiEndpointId,
            String endpointPath,
            String httpMethod,
            String requestIp,
            String userAgent,
            String deviceId,
            String accessStatus,
            Integer responseStatusCode,
            Integer responseTimeMs
    ) {
    }
}
