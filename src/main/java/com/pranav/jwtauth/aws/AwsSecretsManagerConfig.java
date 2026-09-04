package com.pranav.jwtauth.aws;

import com.pranav.jwtauth.config.JwtProperties;
import lombok.extern.slf4j.Slf4j;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;

/**
 * Builds the {@link SecretsManagerClient} used by {@link PublicKeyProvider}. When
 * {@code authz.public-key.region} is blank, the AWS SDK default region provider chain
 * (environment variable, system property, EC2/ECS metadata, etc.) is used.
 */
@Slf4j
public class AwsSecretsManagerConfig {

    public SecretsManagerClient secretsManagerClient(JwtProperties properties) {
        String region = properties.getPublicKey().getRegion();
        SecretsManagerClientBuilder builder = SecretsManagerClient.builder();
        if (region != null && !region.isBlank()) {
            builder.region(Region.of(region));
        }
        log.info("Initializing AWS Secrets Manager client (region={})", region == null || region.isBlank() ? "default-chain" : region);
        return builder.build();
    }
}
