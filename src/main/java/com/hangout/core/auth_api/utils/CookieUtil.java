package com.hangout.core.auth_api.utils;

import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import com.hangout.core.auth_api.config.Constants;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class CookieUtil {
    @Value("${hangout.cookie.domain}")
    private String cookieDomain;
    @Autowired
    @Qualifier("refreshTokenUtil")
    private RefreshTokenUtil refreshTokenUtil;

    public ResponseCookie CreateCookie(String refreshToken) {
        ResponseCookie cookie = ResponseCookie.from(Constants.REFRESH_TOKEN, refreshToken)
                .maxAge(calculateMaxAgeFromDate(refreshTokenUtil.getExpiresAt(refreshToken)))
                .httpOnly(true)
                .sameSite("SameSite")
                .domain(cookieDomain)
                .path("/auth-api/v1/auth/renew")
                .build();
        return cookie;
    }

    public Optional<String> ExtractRefreshTokenFromCookie(HttpServletRequest request) {
        String tokenValue = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (Constants.REFRESH_TOKEN.equals(cookie.getName())) {
                    tokenValue = cookie.getValue();
                    break;
                }
            }
        } else {
            return Optional.empty();
        }
        return tokenValue == null ? Optional.empty() : Optional.of(tokenValue);
    }

    private int calculateMaxAgeFromDate(Date expiryDate) {
        long now = System.currentTimeMillis();
        long expiryMillis = expiryDate.getTime();
        long durationInSeconds = (expiryMillis - now) / 1000;

        // Return as int (clip to 0 if negative, max out if too long)
        if (durationInSeconds < 0)
            return 0;
        if (durationInSeconds > Integer.MAX_VALUE)
            return Integer.MAX_VALUE;
        return (int) durationInSeconds;
    }
}
