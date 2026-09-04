package com.pranav.jwtauth.refresh;

/** Calls the auth service to exchange a valid refresh token for a new access token. */
public interface RefreshTokenClient {

    RefreshTokenResponse refresh(String refreshToken);
}
