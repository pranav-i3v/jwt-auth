package com.pranav.jwtauth.security.filter;

import com.pranav.jwtauth.security.token.JwtAuthenticationToken;
import tools.jackson.databind.ObjectMapper;
import com.pranav.jwtauth.config.JwtProperties;
import com.pranav.jwtauth.exception.AuthzFailureReason;
import com.pranav.jwtauth.exception.JwtAuthenticationException;
import com.pranav.jwtauth.model.AuthenticatedUser;
import com.pranav.jwtauth.model.EndpointAuthorizationResult;
import com.pranav.jwtauth.service.AuthorizationService;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.AntPathMatcher;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Core Spring Security filter of the authz-starter library. Deliberately implements plain
 * {@link Filter} rather than {@code OncePerRequestFilter} so that <em>every</em> dispatch it is
 * registered for is validated independently — including {@code FORWARD}, {@code INCLUDE},
 * {@code ERROR} and {@code ASYNC} dispatches, which {@code OncePerRequestFilter} would short-circuit
 * after the initial {@code REQUEST} dispatch. On each invocation it:
 * <ol>
 *     <li>Skips configured public paths ({@code authz.filter.exclude-paths}).</li>
 *     <li>Extracts and validates the {@code Authorization: Bearer <jwt>} header (401 on failure).</li>
 *     <li>Rejects blacklisted tokens (401).</li>
 *     <li>Populates the {@link org.springframework.security.core.context.SecurityContext}.</li>
 *     <li>Calls the endpoint-authorization stored procedure (403 on denial).</li>
 *     <li>Records the outcome to {@code endpoint_access_log}.</li>
 * </ol>
 */
@Slf4j
public class JwtAuthenticationFilter implements Filter {

    private final AuthenticationManager authenticationManager;
    private final AuthorizationService authorizationService;
    private final JwtProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                    AuthorizationService authorizationService,
                                    JwtProperties properties) {
        this.authenticationManager = authenticationManager;
        this.authorizationService = authorizationService;
        this.properties = properties;
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain)
            throws ServletException, IOException {

        if (!(servletRequest instanceof HttpServletRequest request)
                || !(servletResponse instanceof HttpServletResponse response)) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        if (isExcluded(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        long startedAt = System.currentTimeMillis();
        String endpointPath = request.getRequestURI();
        String httpMethod = request.getMethod();
        String rawToken = extractBearerToken(request);

        AuthenticatedUser user;
        try {
            Authentication authentication = authenticationManager.authenticate(
                    JwtAuthenticationToken.unauthenticated(rawToken, sessionRefreshToken(request)));
            JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken) authentication;
            jwtAuthentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(jwtAuthentication);
            if (jwtAuthentication.getRefreshedAccessToken() != null) {
                response.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + jwtAuthentication.getRefreshedAccessToken());
            }
            user = jwtAuthentication.getPrincipal();
        } catch (JwtAuthenticationException e) {
            log.debug("JWT validation failed for {} {}: {}", httpMethod, endpointPath, e.getMessage());
            writeErrorResponse(response, e.getStatus(), e.getReason().name(), e.getMessage());
            logAccess(null, request, endpointPath, httpMethod, e.getReason().name(), e.getStatus(), startedAt);
            return;
        }

        EndpointAuthorizationResult authorizationResult =
                authorizationService.checkEndpointAuthorization(user, endpointPath, httpMethod);

        if (!authorizationResult.isAllowed()) {
            String reason = authorizationResult.getReasonCode() != null
                    ? authorizationResult.getReasonCode() : AuthzFailureReason.DENIED_NO_PERMISSION.name();
            String message = authorizationResult.getMessage() != null
                    ? authorizationResult.getMessage() : "You do not have permission to access this resource";
            log.warn("Access denied for userId={} on {} {}: {}", user.getUserId(), httpMethod, endpointPath, message);
            writeErrorResponse(response, HttpStatus.FORBIDDEN, reason, message);
            logAccess(user, request, endpointPath, httpMethod, reason, HttpStatus.FORBIDDEN, startedAt);
            return;
        }

        try {
            filterChain.doFilter(request, response);
        } finally {
            logAccess(user, request, endpointPath, httpMethod, "ALLOWED", HttpStatus.valueOf(response.getStatus()), startedAt);
        }
    }

    private boolean isExcluded(HttpServletRequest request) {
        String path = request.getServletPath();
        return properties.getFilter().getExcludePaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    private String extractBearerToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7).trim();
        }
        return null;
    }

    private String sessionRefreshToken(HttpServletRequest request) {
        if (!properties.getRefresh().isEnabled()) {
            return null;
        }
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object value = session.getAttribute(properties.getRefresh().getSessionAttributeName());
        return value instanceof String token ? token : null;
    }

    private void logAccess(AuthenticatedUser user, HttpServletRequest request, String endpointPath, String httpMethod,
                            String status, HttpStatus responseStatus, long startedAt) {
        int elapsedMs = (int) (System.currentTimeMillis() - startedAt);
        AuthorizationService.AccessLogEntry entry = new AuthorizationService.AccessLogEntry(
                user != null ? user.getUserId() : null,
                user != null ? user.getUsername() : null,
                null,
                endpointPath,
                httpMethod,
                request.getRemoteAddr(),
                request.getHeader("User-Agent"),
                request.getHeader("X-Device-Id"),
                status,
                responseStatus.value(),
                elapsedMs);

        if (properties.getAccessLog().isAsync()) {
            authorizationService.logAccessAsync(entry);
        } else {
            authorizationService.logAccess(entry);
        }
    }

    private void writeErrorResponse(HttpServletResponse response, HttpStatus status, String errorCode, String message)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", errorCode);
        body.put("message", message);

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
