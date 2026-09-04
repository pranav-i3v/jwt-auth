package com.pranav.jwtauth.repository;

import com.pranav.jwtauth.repository.entity.TokenBlacklistEntry;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.Repository;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

/**
 * Calls {@code sec.sp_check_endpoint_authorization} as a native query. PostgreSQL exposes a
 * set-returning function through {@code SELECT ... FROM fn(...)}, so no stored-procedure JDBC API
 * is needed - the function is queried like a table. When called this way, the result columns are
 * named after the function's {@code OUT} parameters: {@code p_is_authorized} (bool) and
 * {@code p_authorization_reason} (varchar).
 *
 * <p>The function name is a literal in the query, not the {@code authz.authorization
 * .stored-procedure-name} property: {@code @Query} binds {@code :userId} etc. as JDBC parameter
 * values, and a parameter placeholder cannot stand in for a SQL identifier such as a function name.
 * The {@code sec} schema is likewise a literal, matching the deployed function; if your deployment
 * uses a different schema/name, declare your own {@link EndpointAuthorizationRepository} bean.
 *
 * <p>{@link TokenBlacklistEntry} is only supplied to satisfy the {@code Repository<T, ID>} generic
 * signature Spring Data JPA requires to build the base repository fragment - this repository never
 * reads or writes that entity, it only declares the {@code @Query} method below.
 */
public interface EndpointAuthorizationRepository extends Repository<TokenBlacklistEntry, Long> {

    @Query(value = """
            SELECT p_is_authorized AS allowed,
                   p_authorization_reason AS reasonCode
            FROM sec.sp_check_endpoint_authorization(:userId, :endpointPath, :httpMethod)
            """, nativeQuery = true)
    Optional<EndpointAuthorizationRow> checkEndpointAuthorization(@Param("userId") Long userId,
                                                                   @Param("endpointPath") String endpointPath,
                                                                   @Param("httpMethod") String httpMethod);
}
