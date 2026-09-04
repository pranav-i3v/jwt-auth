package com.pranav.jwtauth.security.provider;

import com.pranav.jwtauth.exception.AuthzFailureReason;
import com.pranav.jwtauth.exception.JwtAuthenticationException;
import com.pranav.jwtauth.exception.JwtValidationException;
import com.pranav.jwtauth.model.AuthenticatedUser;
import com.pranav.jwtauth.config.JwtProperties;
import com.pranav.jwtauth.refresh.RefreshTokenClient;
import com.pranav.jwtauth.refresh.RefreshTokenClientException;
import com.pranav.jwtauth.refresh.RefreshTokenResponse;
import com.pranav.jwtauth.security.token.JwtAuthenticationToken;
import com.pranav.jwtauth.service.AuthorizationService;
import com.pranav.jwtauth.provider.JwtTokenProvider;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Authenticates bearer JWTs by validating their claims and checking token revocation.
 */
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtTokenProvider tokenProvider;
    private final AuthorizationService authorizationService;
    private final RefreshTokenClient refreshTokenClient;
    private final JwtProperties properties;

    public JwtAuthenticationProvider(JwtTokenProvider tokenProvider, AuthorizationService authorizationService,
                                     RefreshTokenClient refreshTokenClient, JwtProperties properties) {
        this.tokenProvider = tokenProvider;
        this.authorizationService = authorizationService;
        this.refreshTokenClient = refreshTokenClient;
        this.properties = properties;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtAuthentication = (JwtAuthenticationToken) authentication;
        try {
            AuthenticatedUser user = tokenProvider.parseAndValidate(jwtAuthentication.getCredentials());
            if (authorizationService.isTokenBlacklisted(user.getTokenId())) {
                throw new JwtValidationException(AuthzFailureReason.TOKEN_BLACKLISTED, "JWT token has been revoked");
            }
            return JwtAuthenticationToken.authenticated(user, authoritiesFor(user));
        } catch (JwtValidationException exception) {
            if (exception.getReason() == AuthzFailureReason.EXPIRED_TOKEN && properties.getRefresh().isEnabled()) {
                return refreshExpiredAuthentication(jwtAuthentication);
            }
            throw new JwtAuthenticationException(exception.getReason(), exception.getMessage(), exception);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private List<GrantedAuthority> authoritiesFor(AuthenticatedUser user) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        Optional.ofNullable(user.getRoles()).orElseGet(java.util.Set::of)
                .forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        Optional.ofNullable(user.getPermissions()).orElseGet(java.util.Set::of)
                .forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
        return authorities;
    }

    private Authentication refreshExpiredAuthentication(JwtAuthenticationToken jwtAuthentication) {
        String refreshToken = jwtAuthentication.getRefreshToken();
//        if (refreshToken == null || refreshToken.isBlank()) {
//            throw new JwtAuthenticationException(AuthzFailureReason.INVALID_TOKEN,
//                    "Refresh token is missing from the session", null);
//        }
        try {
            RefreshTokenResponse response = refreshTokenClient.refresh(refreshToken);
            AuthenticatedUser user = tokenProvider.parseAndValidate(response.accessToken());
            if (authorizationService.isTokenBlacklisted(user.getTokenId())) {
                throw new JwtAuthenticationException(AuthzFailureReason.TOKEN_BLACKLISTED,
                        "JWT token has been revoked", null);
            }
            return JwtAuthenticationToken.authenticated(user, authoritiesFor(user), response.accessToken());
        } catch (RefreshTokenClientException exception) {
            HttpStatus status = exception.isServiceUnavailable() ? HttpStatus.SERVICE_UNAVAILABLE : HttpStatus.UNAUTHORIZED;
            AuthzFailureReason reason = exception.isServiceUnavailable()
                    ? AuthzFailureReason.ERROR : AuthzFailureReason.INVALID_TOKEN;
            throw new JwtAuthenticationException(reason, status, exception.getMessage(), exception);
        } catch (JwtValidationException exception) {
            throw new JwtAuthenticationException(AuthzFailureReason.INVALID_TOKEN,
                    "Auth service returned an invalid access token", exception);
        }
    }
}
