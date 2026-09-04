package com.pranav.jwtauth.security.handler;

import com.pranav.jwtauth.security.filter.JwtAuthenticationFilter;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Defense-in-depth handlers for the (rare) case a request reaches Spring Security's access
 * decision layer without already having been rejected by {@link JwtAuthenticationFilter}.
 * Ensures a consistent JSON error body regardless of which layer rejects the request.
 */
public final class AuthzSecurityHandlers {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private AuthzSecurityHandlers() {
    }

    public static AuthenticationEntryPoint entryPoint() {
        return (HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) ->
                writeError(response, HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED", "Authentication is required to access this resource");
    }

    public static AccessDeniedHandler accessDeniedHandler() {
        return (HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) ->
                writeError(response, HttpStatus.FORBIDDEN, "DENIED_NO_PERMISSION", "You do not have permission to access this resource");
    }

    private static void writeError(HttpServletResponse response, HttpStatus status, String errorCode, String message)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", status.value());
        body.put("error", errorCode);
        body.put("message", message);

        response.getWriter().write(OBJECT_MAPPER.writeValueAsString(body));
    }
}
