package com.pranav.jwtauth.aws;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.pranav.jwtauth.config.JwtProperties;
import com.pranav.jwtauth.exception.PublicKeyResolutionException;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Fetches the RSA public key used to verify RS256-signed JWTs from AWS Secrets Manager,
 * caching the result in-memory and refreshing it once the configured TTL elapses.
 *
 * <p>Thread-safe: concurrent callers during a cache miss block on a single refresh; all other
 * reads are lock-free.
 */
@Slf4j
public class PublicKeyProvider {

    private static final String PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PEM_FOOTER = "-----END PUBLIC KEY-----";

    private final SecretsManagerClient secretsManagerClient;
    private final JwtProperties properties;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ReentrantLock refreshLock = new ReentrantLock();

    private volatile RSAPublicKey cachedKey;
    private volatile long cachedAtEpochMillis = 0L;

    public PublicKeyProvider(SecretsManagerClient secretsManagerClient, JwtProperties properties) {
        this.secretsManagerClient = secretsManagerClient;
        this.properties = properties;
    }

    /**
     * Returns the cached RSA public key, transparently refreshing it from AWS Secrets Manager
     * if it is missing or older than {@code authz.public-key.cache-ttl}.
     */
    public RSAPublicKey getPublicKey() {
        RSAPublicKey key = cachedKey;
        if (key != null && !isExpired()) {
            return key;
        }
        refreshLock.lock();
        try {
            // Re-check after acquiring the lock in case another thread already refreshed.
            if (cachedKey != null && !isExpired()) {
                return cachedKey;
            }
            return fetchAndCache();
        } finally {
            refreshLock.unlock();
        }
    }

    /** Forces a refresh on the next {@link #getPublicKey()} call (e.g. on signature validation failure). */
    public void invalidate() {
        cachedAtEpochMillis = 0L;
    }

    private boolean isExpired() {
        long ttlMillis = properties.getPublicKey().getCacheTtl().toMillis();
        return System.currentTimeMillis() - cachedAtEpochMillis > ttlMillis;
    }

    private RSAPublicKey fetchAndCache() {
        log.debug("Fetching JWT public key from AWS Secrets Manager (secretName={})",
                properties.getPublicKey().getSecretName());
        try {
            GetSecretValueRequest request = GetSecretValueRequest.builder()
                    .secretId(properties.getPublicKey().getSecretName())
                    .build();
            GetSecretValueResponse response = secretsManagerClient.getSecretValue(request);
            String pem = extractPem(response.secretString());
            RSAPublicKey publicKey = parsePem(pem);

            this.cachedKey = publicKey;
            this.cachedAtEpochMillis = System.currentTimeMillis();
            log.info("Successfully loaded/refreshed JWT public key from AWS Secrets Manager");
            return publicKey;
        } catch (SecretsManagerException e) {
            if (cachedKey != null) {
                log.warn("Failed to refresh public key from AWS Secrets Manager; serving stale cached key", e);
                return cachedKey;
            }
            throw new PublicKeyResolutionException("Unable to fetch public key from AWS Secrets Manager", e);
        }
    }

    private String extractPem(String secretString) {
        String fieldName = properties.getPublicKey().getSecretJsonField();
        if (fieldName == null || fieldName.isBlank()) {
            return secretString;
        }
        try {
            JsonNode node = objectMapper.readTree(secretString);
            JsonNode value = node.get(fieldName);
            if (value == null || value.isNull()) {
                // Secret isn't JSON-wrapped; fall back to treating the raw string as the PEM key.
                return secretString;
            }
            return value.asText();
        } catch (Exception e) {
            // Not valid JSON - assume the secret value itself is the PEM-encoded key.
            return secretString;
        }
    }

    private RSAPublicKey parsePem(String pem) {
        try {
            String sanitized = pem
                    .replace(PEM_HEADER, "")
                    .replace(PEM_FOOTER, "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(sanitized);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException e) {
            throw new PublicKeyResolutionException("Unable to parse RSA public key PEM from secret", e);
        }
    }
}
