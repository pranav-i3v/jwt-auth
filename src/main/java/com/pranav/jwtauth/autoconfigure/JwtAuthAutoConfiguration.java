package com.pranav.jwtauth.autoconfigure;

import com.pranav.jwtauth.aws.AwsSecretsManagerConfig;
import com.pranav.jwtauth.aws.PublicKeyProvider;
import com.pranav.jwtauth.config.JwtProperties;
import com.pranav.jwtauth.repository.EndpointAccessLogRepository;
import com.pranav.jwtauth.repository.EndpointAuthorizationRepository;
import com.pranav.jwtauth.repository.TokenBlacklistRepository;
import com.pranav.jwtauth.security.handler.AuthzSecurityHandlers;
import com.pranav.jwtauth.security.filter.JwtAuthenticationFilter;
import com.pranav.jwtauth.security.provider.JwtAuthenticationProvider;
import com.pranav.jwtauth.refresh.AuthServiceRefreshTokenClient;
import com.pranav.jwtauth.refresh.RefreshTokenClient;
import com.pranav.jwtauth.service.AuthorizationService;
import com.pranav.jwtauth.provider.JwtTokenProvider;
import jakarta.persistence.EntityManagerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.core.task.AsyncTaskExecutor;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.transaction.PlatformTransactionManager;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

/**
 * Auto-configures the authz-starter (jwt-auth) library for any microservice that adds it as a
 * Maven dependency. Provides:
 * <ul>
 *     <li>AWS Secrets Manager client + cached RSA public key provider</li>
 *     <li>{@link JwtTokenProvider} for JWT validation (RS256)</li>
 *     <li>Repositories for the blacklist, authorization procedure and access log, plus
 *         {@link AuthorizationService} holding the policy around them</li>
 *     <li>{@link JwtAuthenticationFilter} wired into a default, stateless {@link SecurityFilterChain}</li>
 * </ul>
 * Every bean is {@code @ConditionalOnMissingBean}, so consuming applications can override any part
 * of the wiring (e.g. supply their own {@link SecurityFilterChain}) without conflicts.
 *
 * <p>All three Spring Data JPA repositories are built programmatically through
 * {@link JpaRepositoryFactory} rather than declared with {@code @EnableJpaRepositories}. That
 * annotation registers a {@code JpaRepositoryFactoryBean}, which would satisfy the
 * {@code @ConditionalOnMissingBean} guard on Boot's own {@code DataJpaRepositoriesAutoConfiguration}
 * and silently stop the <em>consuming</em> application's repositories from being scanned. Building
 * the proxies here exposes beans typed as the repository interfaces only, so Boot's scanning is
 * untouched. The trade-off is that these proxies carry no transaction advice, so
 * {@link AuthorizationService} demarcates the access-log write itself.
 */
@AutoConfiguration(after = HibernateJpaAutoConfiguration.class)
@EnableConfigurationProperties(JwtProperties.class)
@EnableAsync
@Import(AuthzEntityScanRegistrar.class)
@ConditionalOnProperty(prefix = "authz", name = "enabled", havingValue = "true", matchIfMissing = true)
public class JwtAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public SecretsManagerClient authzSecretsManagerClient(JwtProperties properties) {
        return new AwsSecretsManagerConfig().secretsManagerClient(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public PublicKeyProvider publicKeyProvider(SecretsManagerClient secretsManagerClient, JwtProperties properties) {
        return new PublicKeyProvider(secretsManagerClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenProvider jwtTokenProvider(PublicKeyProvider publicKeyProvider, JwtProperties properties) {
        return new JwtTokenProvider(publicKeyProvider, properties);
    }

    @Bean
    @ConditionalOnMissingBean
    public TokenBlacklistRepository tokenBlacklistRepository(EntityManagerFactory entityManagerFactory) {
        return repositoryFactory(entityManagerFactory).getRepository(TokenBlacklistRepository.class);
    }

    @Bean
    @ConditionalOnMissingBean
    public EndpointAccessLogRepository endpointAccessLogRepository(EntityManagerFactory entityManagerFactory) {
        return repositoryFactory(entityManagerFactory).getRepository(EndpointAccessLogRepository.class);
    }

    @Bean
    @ConditionalOnMissingBean
    public EndpointAuthorizationRepository endpointAuthorizationRepository(EntityManagerFactory entityManagerFactory) {
        return repositoryFactory(entityManagerFactory).getRepository(EndpointAuthorizationRepository.class);
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthorizationService authorizationService(TokenBlacklistRepository tokenBlacklistRepository,
                                                       EndpointAuthorizationRepository endpointAuthorizationRepository,
                                                       EndpointAccessLogRepository endpointAccessLogRepository,
                                                       PlatformTransactionManager transactionManager,
                                                       JwtProperties properties) {
        return new AuthorizationService(tokenBlacklistRepository, endpointAuthorizationRepository,
                endpointAccessLogRepository, transactionManager, properties);
    }

    /**
     * Uses the transaction-aware shared {@code EntityManager} proxy, exactly as Spring Data's own
     * {@code JpaRepositoryFactoryBean} does, so repository calls join whatever transaction is active
     * on the calling thread.
     */
    private static JpaRepositoryFactory repositoryFactory(EntityManagerFactory entityManagerFactory) {
        return new JpaRepositoryFactory(SharedEntityManagerCreator.createSharedEntityManager(entityManagerFactory));
    }

    @Bean
    @ConditionalOnMissingBean(name = "authzAccessLogExecutor")
    public AsyncTaskExecutor authzAccessLogExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setThreadNamePrefix("authz-access-log-");
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(8);
        executor.setQueueCapacity(500);
        executor.initialize();
        return executor;
    }

    @Bean
    @ConditionalOnMissingBean
    public RefreshTokenClient refreshTokenClient(WebClient.Builder webClientBuilder, JwtProperties properties) {
        return new AuthServiceRefreshTokenClient(webClientBuilder, properties.getRefresh());
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationProvider jwtAuthenticationProvider(JwtTokenProvider jwtTokenProvider,
                                                                AuthorizationService authorizationService,
                                                                RefreshTokenClient refreshTokenClient,
                                                                JwtProperties properties) {
        return new JwtAuthenticationProvider(jwtTokenProvider, authorizationService, refreshTokenClient, properties);
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationManager.class)
    public AuthenticationManager jwtAuthenticationManager(JwtAuthenticationProvider jwtAuthenticationProvider) {
        return new ProviderManager(jwtAuthenticationProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(AuthenticationManager authenticationManager,
                                                            AuthorizationService authorizationService,
                                                            JwtProperties properties) {
        return new JwtAuthenticationFilter(authenticationManager, authorizationService, properties);
    }

    /**
     * Default stateless security filter chain. Consuming applications that already define their
     * own {@link SecurityFilterChain} bean take full precedence over this default.
     */
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain authzSecurityFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter,
                                                          JwtProperties properties) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .authorizeHttpRequests(auth -> {
                    properties.getFilter().getExcludePaths().forEach(pattern -> auth.requestMatchers(pattern).permitAll());
                    auth.anyRequest().authenticated();
                })
                .exceptionHandling(handling -> handling
                        .authenticationEntryPoint(AuthzSecurityHandlers.entryPoint())
                        .accessDeniedHandler(AuthzSecurityHandlers.accessDeniedHandler()))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

}
