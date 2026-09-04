package com.pranav.jwtauth.security.token;

import com.pranav.jwtauth.model.AuthenticatedUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

/**
 * Spring Security authentication request/result for a bearer JWT.
 */
public final class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final AuthenticatedUser principal;
    private final String credentials;
    private final String refreshToken;
    private final String refreshedAccessToken;

    private JwtAuthenticationToken(AuthenticatedUser principal, String credentials,
                                   String refreshToken, String refreshedAccessToken,
                                   Collection<? extends GrantedAuthority> authorities, boolean authenticated) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        this.refreshToken = refreshToken;
        this.refreshedAccessToken = refreshedAccessToken;
        setAuthenticated(authenticated);
    }

    /** Creates an unauthenticated request containing the compact bearer token. */
    public static JwtAuthenticationToken unauthenticated(String rawToken) {
        return unauthenticated(rawToken, null);
    }

    /** Creates an unauthenticated request with an optional session refresh token. */
    public static JwtAuthenticationToken unauthenticated(String rawToken, String refreshToken) {
        return new JwtAuthenticationToken(null, rawToken, refreshToken, null, List.of(), false);
    }

    /** Creates an authenticated result containing the validated JWT principal. */
    public static JwtAuthenticationToken authenticated(AuthenticatedUser user,
                                                        Collection<? extends GrantedAuthority> authorities) {
        return authenticated(user, authorities, null);
    }

    /** Creates an authenticated result and, when applicable, carries the replacement access token. */
    public static JwtAuthenticationToken authenticated(AuthenticatedUser user,
                                                        Collection<? extends GrantedAuthority> authorities,
                                                        String refreshedAccessToken) {
        return new JwtAuthenticationToken(user, null, null, refreshedAccessToken, authorities, true);
    }

    @Override
    public AuthenticatedUser getPrincipal() {
        return principal;
    }

    @Override
    public String getCredentials() {
        return credentials;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getRefreshedAccessToken() {
        return refreshedAccessToken;
    }
}
