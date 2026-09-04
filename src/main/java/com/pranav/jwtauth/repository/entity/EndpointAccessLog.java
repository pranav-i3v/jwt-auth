package com.pranav.jwtauth.repository.entity;

import com.pranav.jwtauth.repository.enums.AccessStatusEnum;
import com.pranav.jwtauth.security.filter.JwtAuthenticationFilter;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

/**
 * JPA mapping for the {@code endpoint_access_log} table: one row per authorization decision made
 * by {@link JwtAuthenticationFilter} (allowed, 401 or 403).
 *
 * <p>Insert-only - this library never reads or updates access-log rows.
 */
@Entity
@Table(name = "endpoint_access_log")
@Getter
@Setter
@NoArgsConstructor
public class EndpointAccessLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "username")
    private String username;

    @Column(name = "api_endpoint_id")
    private Long apiEndpointId;

    @Column(name = "endpoint_path")
    private String endpointPath;

    @Column(name = "http_method")
    private String httpMethod;

    @Column(name = "request_ip")
    private String requestIp;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "device_id")
    private String deviceId;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.NAMED_ENUM)
    @Column(name = "access_status", nullable = false, columnDefinition = "access_status_enum")
    private AccessStatusEnum accessStatus;

    @Column(name = "response_status_code")
    private Integer responseStatusCode;

    @Column(name = "response_time_ms")
    private Integer responseTimeMs;

    @Column(name = "accessed_at")
    private Instant accessedAt;
}
