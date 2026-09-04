package com.pranav.jwtauth.token;

import com.pranav.jwtauth.aws.PublicKeyProvider;
import com.pranav.jwtauth.config.JwtProperties;
import com.pranav.jwtauth.exception.AuthzFailureReason;
import com.pranav.jwtauth.exception.JwtValidationException;
import com.pranav.jwtauth.model.AuthenticatedUser;
import com.pranav.jwtauth.provider.JwtTokenProvider;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenProviderTest {

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private JwtTokenProvider tokenProvider;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();

        PublicKeyProvider publicKeyProvider = Mockito.mock(PublicKeyProvider.class);
        Mockito.when(publicKeyProvider.getPublicKey()).thenReturn(publicKey);

        JwtProperties properties = new JwtProperties();
        tokenProvider = new JwtTokenProvider(publicKeyProvider, properties);
    }

    @Test
    void parsesValidTokenIntoAuthenticatedUser() {
        String token = Jwts.builder()
                .subject("42")
                .id("jti-123")
                .claim("username", "jdoe")
                .claim("userType", "SUPPORT_STAFF")
                .claim("roles", List.of("SUPPORT_STAFF"))
                .claim("permissions", List.of("bills:read", "complaints:update"))
                .claim("region", "GJ-VD")
                .claim("zone", "ZONE-01")
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(900)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();

        AuthenticatedUser user = tokenProvider.parseAndValidate(token);

        assertThat(user.getUserId()).isEqualTo(42L);
        assertThat(user.getUsername()).isEqualTo("jdoe");
        assertThat(user.getRoles()).containsExactly("SUPPORT_STAFF");
        assertThat(user.getPermissions()).containsExactlyInAnyOrder("bills:read", "complaints:update");
        assertThat(user.getRegionCode()).isEqualTo("GJ-VD");
        assertThat(user.getTokenId()).isEqualTo("jti-123");
    }

    @Test
    void rejectsExpiredToken() {
        String token = Jwts.builder()
                .subject("42")
                .id("jti-expired")
                .expiration(Date.from(Instant.now().minusSeconds(3600)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();

        assertThatThrownBy(() -> tokenProvider.parseAndValidate(token))
                .isInstanceOf(JwtValidationException.class)
                .satisfies(e -> assertThat(((JwtValidationException) e).getReason()).isEqualTo(AuthzFailureReason.EXPIRED_TOKEN));
    }

    @Test
    void rejectsTokenSignedByDifferentKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAPrivateKey otherPrivateKey = (RSAPrivateKey) generator.generateKeyPair().getPrivate();

        String token = Jwts.builder()
                .subject("42")
                .expiration(Date.from(Instant.now().plusSeconds(900)))
                .signWith(otherPrivateKey, Jwts.SIG.RS256)
                .compact();

        assertThatThrownBy(() -> tokenProvider.parseAndValidate(token))
                .isInstanceOf(JwtValidationException.class)
                .satisfies(e -> assertThat(((JwtValidationException) e).getReason()).isEqualTo(AuthzFailureReason.INVALID_SIGNATURE));
    }

    @Test
    void rejectsMissingToken() {
        assertThatThrownBy(() -> tokenProvider.parseAndValidate(null))
                .isInstanceOf(JwtValidationException.class)
                .satisfies(e -> assertThat(((JwtValidationException) e).getReason()).isEqualTo(AuthzFailureReason.MISSING_TOKEN));
    }
}
