package com.pranav.jwtauth.refresh;

import com.pranav.jwtauth.config.JwtProperties;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.time.Duration;

/** Default {@link RefreshTokenClient} implementation for the auth-service HTTP API. */
public class AuthServiceRefreshTokenClient implements RefreshTokenClient {

    private final WebClient webClient;
    private final JwtProperties.Refresh properties;

    public AuthServiceRefreshTokenClient(WebClient.Builder webClientBuilder, JwtProperties.Refresh properties) {
        this.webClient = webClientBuilder.baseUrl(properties.getAuthServiceBaseUrl())
                .build();
        this.properties = properties;
    }

    @Override
    public RefreshTokenResponse refresh(String refreshToken) {
        try {
            RefreshTokenResponse response = webClient.post()
                    .uri(properties.getEndpoint())
                    .contentType(MediaType.APPLICATION_JSON)
//                    .bodyValue(new RefreshTokenRequest(refreshToken))
                    .retrieve()
                    .bodyToMono(RefreshTokenResponse.class)
                    .block(Duration.ofMillis(properties.getReadTimeout().toMillis()));
            if (response == null || response.accessToken() == null || response.accessToken().isBlank()) {
                throw RefreshTokenClientException.rejected(null);
            }
            return response;
        } catch (RefreshTokenClientException exception) {
            throw exception;
        } catch (WebClientResponseException exception) {
            if (exception.getStatusCode().is4xxClientError()) {
                throw RefreshTokenClientException.rejected(exception);
            }
            throw RefreshTokenClientException.unavailable(exception);
        } catch (WebClientRequestException exception) {
            throw RefreshTokenClientException.unavailable(exception);
        } catch (RuntimeException exception) {
            throw RefreshTokenClientException.unavailable(exception);
        }
    }

    private record RefreshTokenRequest(String refreshToken) {
    }
}
