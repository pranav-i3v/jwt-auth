package com.pranav.jwtauth.repository;

import com.pranav.jwtauth.repository.entity.EndpointAccessLog;
import org.springframework.data.repository.Repository;

/**
 * Spring Data JPA repository over {@code endpoint_access_log}.
 *
 * <p>Only {@code save} is exposed - the library appends audit rows and never reads or deletes them.
 * Writes require an active transaction, which {@link com.pranav.jwtauth.service.AuthorizationService}
 * supplies.
 */
public interface EndpointAccessLogRepository extends Repository<EndpointAccessLog, Long> {

    EndpointAccessLog save(EndpointAccessLog accessLog);
}
