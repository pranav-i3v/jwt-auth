package com.pranav.jwtauth.exception;

/**
 * Thrown when the RSA public key cannot be fetched or parsed from AWS Secrets Manager.
 */
public class PublicKeyResolutionException extends RuntimeException {

    public PublicKeyResolutionException(String message, Throwable cause) {
        super(message, cause);
    }

    public PublicKeyResolutionException(String message) {
        super(message);
    }
}
