package com.pranav.jwtauth.autoconfigure;

import com.pranav.jwtauth.config.JwtProperties;
import com.pranav.jwtauth.repository.EndpointAccessLogRepository;
import com.pranav.jwtauth.repository.EndpointAuthorizationRepository;
import com.pranav.jwtauth.repository.TokenBlacklistRepository;
import com.pranav.jwtauth.repository.entity.TokenBlacklistEntry;
import com.pranav.jwtauth.service.AuthorizationService;
import jakarta.persistence.EntityManagerFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.AutoConfigurationPackages;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.persistence.autoconfigure.EntityScanPackages;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.transaction.autoconfigure.TransactionAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the JPA repository wiring the library contributes to a consuming application: that its
 * entities are scanned, that the programmatically built Spring Data repositories resolve their
 * queries, and that {@link AuthorizationService} can write an access-log row with no ambient
 * transaction (the proxies built by {@code JpaRepositoryFactory} carry no transaction advice).
 */
class AuthzRepositoryWiringTests {

    private static final String LIBRARY_ENTITY_PACKAGE = TokenBlacklistEntry.class.getPackageName();

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    DataSourceAutoConfiguration.class,
                    HibernateJpaAutoConfiguration.class,
                    TransactionAutoConfiguration.class))
            .withUserConfiguration(AuthzRepositoryConfiguration.class)
            .withPropertyValues(
                    "spring.datasource.url=jdbc:h2:mem:authz-" + UUID.randomUUID(),
                    "spring.jpa.hibernate.ddl-auto=create-drop");

    @Test
    void blacklistRepositoryResolvesAgainstTheLibraryEntity() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            TokenBlacklistRepository repository = context.getBean(TokenBlacklistRepository.class);
            JdbcTemplate jdbcTemplate = new JdbcTemplate(context.getBean(DataSource.class));

            assertThat(repository.existsByTokenJtiAndExpiresAtAfter("jti-live", Instant.now())).isFalse();

            insertBlacklistRow(jdbcTemplate, "jti-live", Instant.now().plus(1, ChronoUnit.HOURS));
            insertBlacklistRow(jdbcTemplate, "jti-stale", Instant.now().minus(1, ChronoUnit.HOURS));

            assertThat(repository.existsByTokenJtiAndExpiresAtAfter("jti-live", Instant.now())).isTrue();
            assertThat(repository.existsByTokenJtiAndExpiresAtAfter("jti-stale", Instant.now())).isFalse();
        });
    }

    @Test
    void serviceReadsTheBlacklistAndWritesAccessLogRows() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            AuthorizationService service = context.getBean(AuthorizationService.class);
            JdbcTemplate jdbcTemplate = new JdbcTemplate(context.getBean(DataSource.class));

            assertThat(service.isTokenBlacklisted("jti-revoked")).isFalse();
            insertBlacklistRow(jdbcTemplate, "jti-revoked", Instant.now().plus(1, ChronoUnit.HOURS));
            assertThat(service.isTokenBlacklisted("jti-revoked")).isTrue();

            service.logAccess(new AuthorizationService.AccessLogEntry(7L, "pranav", null, "/api/orders",
                    "GET", "10.0.0.1", "JUnit", "device-1", "ALLOWED", 200, 12));

            assertThat(jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM endpoint_access_log WHERE user_id = 7 AND access_status = 'ALLOWED'",
                    Integer.class)).isEqualTo(1);
        });
    }

    @Test
    void registrarKeepsApplicationPackagesWhenApplicationDeclaredNoEntityScan() {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        AutoConfigurationPackages.register(beanFactory, "com.example.app");

        registrar(beanFactory).registerBeanDefinitions(null, beanFactory);

        assertThat(EntityScanPackages.get(beanFactory).getPackageNames())
                .containsExactlyInAnyOrder(LIBRARY_ENTITY_PACKAGE, "com.example.app");
    }

    @Test
    void registrarDefersToAnApplicationDeclaredEntityScan() {
        DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
        AutoConfigurationPackages.register(beanFactory, "com.example.app");
        EntityScanPackages.register(beanFactory, "com.example.chosen.entities");

        registrar(beanFactory).registerBeanDefinitions(null, beanFactory);

        assertThat(EntityScanPackages.get(beanFactory).getPackageNames())
                .containsExactlyInAnyOrder(LIBRARY_ENTITY_PACKAGE, "com.example.chosen.entities");
    }

    private static AuthzEntityScanRegistrar registrar(DefaultListableBeanFactory beanFactory) {
        AuthzEntityScanRegistrar registrar = new AuthzEntityScanRegistrar();
        registrar.setBeanFactory(beanFactory);
        return registrar;
    }

    private static void insertBlacklistRow(JdbcTemplate jdbcTemplate, String tokenJti, Instant expiresAt) {
        jdbcTemplate.update("INSERT INTO token_blacklist (token_jti, expires_at) VALUES (?, ?)",
                tokenJti, java.sql.Timestamp.from(expiresAt));
    }

    /**
     * Wires the repositories and service through the real {@link JwtAuthAutoConfiguration} bean
     * methods, so this test covers the shipped wiring rather than a copy of it.
     */
    @Configuration(proxyBeanMethods = false)
    @Import(AuthzEntityScanRegistrar.class)
    static class AuthzRepositoryConfiguration {

        private final JwtAuthAutoConfiguration autoConfiguration = new JwtAuthAutoConfiguration();

        @Bean
        JwtProperties jwtProperties() {
            return new JwtProperties();
        }

        @Bean
        TokenBlacklistRepository tokenBlacklistRepository(EntityManagerFactory entityManagerFactory) {
            return autoConfiguration.tokenBlacklistRepository(entityManagerFactory);
        }

        @Bean
        EndpointAccessLogRepository endpointAccessLogRepository(EntityManagerFactory entityManagerFactory) {
            return autoConfiguration.endpointAccessLogRepository(entityManagerFactory);
        }

        @Bean
        EndpointAuthorizationRepository endpointAuthorizationRepository(EntityManagerFactory entityManagerFactory) {
            return autoConfiguration.endpointAuthorizationRepository(entityManagerFactory);
        }

        @Bean
        AuthorizationService authorizationService(TokenBlacklistRepository tokenBlacklistRepository,
                                                  EndpointAuthorizationRepository endpointAuthorizationRepository,
                                                  EndpointAccessLogRepository endpointAccessLogRepository,
                                                  PlatformTransactionManager transactionManager,
                                                  JwtProperties properties) {
            return autoConfiguration.authorizationService(tokenBlacklistRepository, endpointAuthorizationRepository,
                    endpointAccessLogRepository, transactionManager, properties);
        }
    }
}
