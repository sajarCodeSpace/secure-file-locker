package com.sajar.securefilelocker.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Token Bucket Rate Limiter Filter to protect computationally expensive endpoints
 * (such as PBKDF2 key derivation and authentication) against brute-force and DoS attacks.
 */
@Component
@Slf4j
public class RateLimitingFilter extends OncePerRequestFilter {

    private static class TokenBucket {
        private final long capacity;
        private final double refillRatePerSecond;
        private double tokens;
        private long lastRefillTimestamp;

        public TokenBucket(long capacity, double refillRatePerSecond) {
            this.capacity = capacity;
            this.refillRatePerSecond = refillRatePerSecond;
            this.tokens = capacity;
            this.lastRefillTimestamp = System.nanoTime();
        }

        public synchronized boolean tryConsume() {
            long now = System.nanoTime();
            double elapsedSeconds = (now - lastRefillTimestamp) / 1_000_000_000.0;
            tokens = Math.min(capacity, tokens + elapsedSeconds * refillRatePerSecond);
            lastRefillTimestamp = now;

            if (tokens >= 1.0) {
                tokens -= 1.0;
                return true;
            }
            return false;
        }
    }

    private final Map<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    // 10 requests max burst, refilling at 1 token every 6 seconds (10/min) for auth
    private static final long AUTH_CAPACITY = 20;
    private static final double AUTH_REFILL_RATE = 20.0 / 60.0;

    // 15 requests max burst, refilling at 15/min for decryption
    private static final long DECRYPT_CAPACITY = 30;
    private static final double DECRYPT_REFILL_RATE = 30.0 / 60.0;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String clientIp = getClientIp(request);

        boolean rateLimited = false;

        if (path.startsWith("/api/auth/login") || path.startsWith("/api/auth/register")) {
            String bucketKey = "auth:" + clientIp;
            TokenBucket bucket = buckets.computeIfAbsent(bucketKey, k -> new TokenBucket(AUTH_CAPACITY, AUTH_REFILL_RATE));
            if (!bucket.tryConsume()) {
                rateLimited = true;
            }
        } else if (path.matches("^/api/files/\\d+/download$")) {
            String bucketKey = "download:" + clientIp;
            TokenBucket bucket = buckets.computeIfAbsent(bucketKey, k -> new TokenBucket(DECRYPT_CAPACITY, DECRYPT_REFILL_RATE));
            if (!bucket.tryConsume()) {
                rateLimited = true;
            }
        }

        if (rateLimited) {
            log.warn("Rate limit exceeded for IP: {} on endpoint: {}", clientIp, path);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(String.format(
                    "{\"timestamp\":\"%s\",\"status\":429,\"error\":\"Too Many Requests\",\"message\":\"Rate limit exceeded. Please try again later.\"}",
                    Instant.now()
            ));
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isBlank()) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0].trim();
    }
}
