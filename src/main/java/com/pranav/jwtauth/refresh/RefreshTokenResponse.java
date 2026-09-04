package com.pranav.jwtauth.refresh;

/** Response body returned by the auth-service refresh endpoint. */
public record RefreshTokenResponse(String accessToken, Long expiresIn) {
}
