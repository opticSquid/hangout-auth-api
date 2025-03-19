package com.hangout.core.auth_api.utils;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.opentelemetry.instrumentation.annotations.WithSpan;

@Component
public class RefreshTokenUtil implements JwtUtil {
    @Value("${hangout.jwt.refresh-token.secret}")
    private String REFRESH_SECRET_KEY;
    @Value("${hangout.jwt.refresh-token.long-term-expiry}")
    private long LONG_TERM_EXPIRY;
    @Value("${hangout.jwt.refresh-token.short-term-expiry}")
    private long SHORT_TERM_EXPIRY;

    @Override
    @WithSpan(value = "generate-token - refresh-token (long term)")
    public String generateToken(String username, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        // expiration is 7 days
        return createToken(username, claims, LONG_TERM_EXPIRY);
    }

    @WithSpan(value = "generate-token - refresh-token (short term)")
    public String generateTokenShortTerm(String username, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        // expiration is 10 minutes
        return createToken(username, claims, SHORT_TERM_EXPIRY);
    }

    @Override
    @WithSpan(value = "validate-token - refresh-token")
    public Boolean validateToken(String token) {
        Date expirationTime = this.extractAllClaims(token).getExpiration();
        return !expirationTime.before(new Date());
    }

    @Override
    @WithSpan(value = "get-expires-at - refresh-token")
    public Date getExpiresAt(String token) {
        Date issueTime = this.extractAllClaims(token).getExpiration();
        return issueTime;
    }

    @Override
    @WithSpan(value = "get-username - refresh-token")
    public String getUsername(String token) {
        return this.extractAllClaims(token).getSubject();
    }

    @Override
    @WithSpan(value = "get-device-id - refresh-token")
    public UUID getDeviceId(String token) {
        return UUID.fromString((String) extractAllClaims(token).getOrDefault("deviceId", null));
    }

    @WithSpan(value = "get signing key - ")
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(REFRESH_SECRET_KEY.getBytes());
    }

    // ? 'long', not 'Long' is used for compatibility with int because access key
    // ? expiration will fall in range of int
    // ? but refresh key expiration may overflow int boundary
    @WithSpan(value = "create token - refresh-token")
    private String createToken(String subject, Map<String, Object> claims, long expiration) {
        long currentTimeStamp = System.currentTimeMillis();
        return Jwts.builder()
                .header().empty().add("typ", "ACS_JWT")
                .and()
                .subject(subject)
                .claims(claims)
                .issuedAt(new Date(currentTimeStamp))
                .expiration(new Date(currentTimeStamp + expiration))
                .signWith(this.getSigningKey())
                .compact();

    }

    @WithSpan(value = "extract all claims - refresh-token")
    private Claims extractAllClaims(String token) throws ExpiredJwtException {
        return Jwts.parser()
                .verifyWith(this.getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
