package com.sajar.securefilelocker.security;

/** The security principal placed in the SecurityContext after a JWT is validated. */
public record AuthenticatedUser(Long id, String username) {}
