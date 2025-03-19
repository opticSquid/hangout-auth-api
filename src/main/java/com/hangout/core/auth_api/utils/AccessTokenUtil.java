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
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class AccessTokenUtil implements JwtUtil {
    @Value("${hangout.jwt.access-token.secret}")
    private String ACCESS_SECRET_KEY;
    @Value("${hangout.jwt.access-token.expiry}")
    private Long EXPIRY_TIME;

    @Override
    @WithSpan(value = "generate-token - access-token")
    public String generateToken(String username, UUID deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("deviceId", deviceId);
        // expiration is 5 minutes
        return createToken(username, claims, EXPIRY_TIME);
    }

    @Override
    @WithSpan(value = "validate-token - access-token")
    public Boolean validateToken(String token) {
        log.debug("Validating access token: {}", token);
        if (!token.isEmpty()) {
            Date expirationTime = this.extractAllClaims(token).getExpiration();
            log.debug("token expiration: {}", expirationTime);
            // check if the expirtation is in past of current instant
            return !expirationTime.before(new Date());
        } else {
            return false;
        }
    }

    @Override
    @WithSpan(value = "get-expires-at - access-token")
    public Date getExpiresAt(String token) {
        Date issueTime = this.extractAllClaims(token).getExpiration();
        return issueTime;
    }

    @Override
    @WithSpan(value = "get-username - access-token")
    public String getUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    @Override
    @WithSpan(value = "get-device-id - access-token")
    public UUID getDeviceId(String token) {
        return UUID.fromString((String) extractAllClaims(token).getOrDefault("deviceId", null));
    }

    @WithSpan(value = "get signing key - access-token")
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(ACCESS_SECRET_KEY.getBytes());
    }

    // ? 'long', not 'Long' is used for compatibility with int because access key
    // ? expiration will fall in range of int
    // ? but refresh key expiration may overflow int boundary
    @WithSpan(value = "create token - access-token")
    private String createToken(String subject, Map<String, Object> claims, long expiration) {
        long currentTimeStamp = System.currentTimeMillis();
        return Jwts.builder()
                .claims(claims)
                .subject(subject)
                .header().empty().add("typ", "JWT")
                .and()
                .issuedAt(new Date(currentTimeStamp))
                .expiration(new Date(currentTimeStamp + expiration))
                .signWith(this.getSigningKey())
                .compact();

    }

    @WithSpan(value = "extract all claims - access-token")
    private Claims extractAllClaims(String token) throws ExpiredJwtException {
        return Jwts.parser()
                .verifyWith(this.getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
