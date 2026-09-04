package com.pranav.jwtauth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for the authz-starter (jwt-auth) library.
 *
 * <p>All properties are bound from the {@code authz} prefix in the consuming
 * microservice's {@code application.yml}, e.g.:
 *
 * <pre>
 * authz:
 *   enabled: true
 *   issuer: gas-auth-service
 *   clock-skew-seconds: 30
 *   public-key:
 *     secret-name: gas/auth/jwt-public-key
 *     region: ap-south-1
 *     cache-ttl: 1h
 *   filter:
 *     exclude-paths:
 *       - /actuator/**
 *       - /swagger-ui/**
 *   authorization:
 *     enabled: true
 *     stored-procedure-name: sp_check_endpoint_authorization
 *   access-log:
 *     enabled: true
 * </pre>
 */
@Data
@ConfigurationProperties(prefix = "authz")
public class JwtProperties {

    /**
     * Master switch for the entire authz-starter auto-configuration.
     */
    private boolean enabled = true;

    /**
     * Expected JWT {@code iss} (issuer) claim. If blank, issuer is not validated.
     */
    private String issuer = "";

    /**
     * Allowed clock skew (in seconds) when validating {@code exp}/{@code nbf} claims.
     */
    private long clockSkewSeconds = 30;

    @NestedConfigurationProperty
    private PublicKey publicKey = new PublicKey();

    @NestedConfigurationProperty
    private Filter filter = new Filter();

    @NestedConfigurationProperty
    private Authorization authorization = new Authorization();

    @NestedConfigurationProperty
    private AccessLog accessLog = new AccessLog();

    @NestedConfigurationProperty
    private Blacklist blacklist = new Blacklist();

    @NestedConfigurationProperty
    private Refresh refresh = new Refresh();

    @Data
    public static class PublicKey {
        /**
         * Name/ARN of the secret in AWS Secrets Manager holding the RSA public key (PEM, X.509 SubjectPublicKeyInfo).
         */
        private String secretName = "gas/auth/rsa-public-key";

        /**
         * AWS region for the Secrets Manager client. If blank, the default AWS region provider chain is used.
         */
        private String region = "";

        /**
         * How long the fetched public key is cached in-memory before being refreshed from AWS Secrets Manager.
         */
        private Duration cacheTtl = Duration.ofHours(1);

        /**
         * JSON field name inside the secret value that holds the PEM-encoded public key.
         * If blank, the entire secret string value is treated as the PEM key.
         */
        private String secretJsonField = "JWT_PUBLIC_KEY";
    }

    @Data
    public static class Filter {
        /**
         * Ant-style path patterns that bypass JWT authentication entirely (health checks, docs, etc.).
         */
        private List<String> excludePaths = new ArrayList<>(List.of(
                "/actuator/**",
                "/swagger-ui/**",
                "/v3/api-docs/**"
        ));

        /**
         * Order of the JWT authentication filter in the Spring Security filter chain.
         */
        private int order = -100;
    }

    @Data
    public static class Authorization {
        /**
         * Whether to call the endpoint-authorization stored procedure for every authenticated request.
         */
        private boolean enabled = true;

        /**
         * Name of the SQL function used to validate endpoint access.
         * Expected signature: sp_check_endpoint_authorization(user_id, endpoint_path, http_method)
         *
         * <p>Not read by the default {@code EndpointAuthorizationRepository}: its {@code @Query} is a
         * compile-time native query, so the function name is a literal, not a bind parameter. This
         * property only takes effect if you supply your own {@code EndpointAuthorizationRepository}
         * bean that honours it.
         */
        private String storedProcedureName = "sp_check_endpoint_authorization";

        /**
         * Fail-open (allow request) when the authorization stored procedure call errors out.
         * Defaults to false (fail-closed / secure by default).
         */
        private boolean failOpenOnError = false;
    }

    @Data
    public static class AccessLog {
        /**
         * Whether to record every authenticated request into the endpoint_access_log table.
         */
        private boolean enabled = true;

        /**
         * Whether access logging is performed asynchronously (recommended) to avoid adding request latency.
         */
        private boolean async = true;
    }

    @Data
    public static class Blacklist {
        /**
         * Whether to check the token_blacklist table before honoring a JWT.
         */
        private boolean enabled = true;
    }

    @Data
    public static class Refresh {
        /** Enables access-token refresh through the configured auth service. */
        private boolean enabled = false;

        /** Base URL of the service that owns refresh-token validation and access-token issuance. */
        private String authServiceBaseUrl = "";

        /** Path of the auth-service refresh endpoint. */
        private String endpoint = "/auth/refresh-token";

        /** Session attribute containing the refresh token established during login. */
        private String sessionAttributeName = "AUTHZ_REFRESH_TOKEN";

        private Duration connectTimeout = Duration.ofSeconds(2);

        private Duration readTimeout = Duration.ofSeconds(5);
    }
}
