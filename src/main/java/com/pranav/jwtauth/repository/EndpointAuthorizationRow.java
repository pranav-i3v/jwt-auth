package com.pranav.jwtauth.repository;

/**
 * Interface projection for a row returned by {@link EndpointAuthorizationRepository}. Spring Data
 * matches each accessor to the column alias of the same name (case-insensitive), so the routine's
 * result columns can be reordered without breaking the mapping.
 */
public interface EndpointAuthorizationRow {

    boolean isAllowed();

    String getReasonCode();
}
