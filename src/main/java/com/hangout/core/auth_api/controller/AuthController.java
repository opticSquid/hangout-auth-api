package com.hangout.core.auth_api.controller;

import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.hangout.core.auth_api.config.Constants;
import com.hangout.core.auth_api.dto.internal.AuthResult;
import com.hangout.core.auth_api.dto.request.ExistingUserCreds;
import com.hangout.core.auth_api.dto.request.NewUser;
import com.hangout.core.auth_api.dto.response.AuthResponse;
import com.hangout.core.auth_api.dto.response.DefaultResponse;
import com.hangout.core.auth_api.exceptions.UnauthorizedAccessException;
import com.hangout.core.auth_api.service.AccessService;
import com.hangout.core.auth_api.service.UserDetailsServiceImpl;
import com.hangout.core.auth_api.utils.DeviceUtil;
import com.hangout.core.auth_api.utils.RefreshTokenUtil;

import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.instrumentation.annotations.WithSpan;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/v1/auth/")
@Tag(name = "Public Endpoints")
@RequiredArgsConstructor
@Slf4j
public class AuthController {
    @Value("${hangout.cookie.domain}")
    private String cookieDomain;
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private AccessService accessService;

    @Autowired
    @Qualifier("refreshTokenUtil")
    private RefreshTokenUtil refreshTokenUtil;

    @PostMapping("/signup")
    @WithSpan(kind = SpanKind.SERVER, value = "signup controller")
    @Operation(summary = "Add new user")
    public ResponseEntity<DefaultResponse> signup(@RequestBody NewUser user) {
        try {
            this.userDetailsService.addNewUser(user);
            return new ResponseEntity<>(new DefaultResponse("Verification mail sent"), HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(new DefaultResponse("User already exists"), HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping("/verify")
    @WithSpan(kind = SpanKind.SERVER, value = "verify-email controller")
    @Operation(summary = "verify new user's email")
    public ResponseEntity<DefaultResponse> verifyAccount(@RequestParam String token) {
        log.debug("token received for verification: {}", token);
        String res = this.userDetailsService.verifyToken(token);
        return new ResponseEntity<>(new DefaultResponse(res), HttpStatus.OK);
    }

    @GetMapping("/trust-device")
    @WithSpan(kind = SpanKind.SERVER, value = "trust-device controller")
    @Operation(summary = "update device details to trust the current device and unlock all functionalities")
    public ResponseEntity<AuthResponse> trustDevice(@RequestHeader("Authorization") String accessToken,
            HttpServletRequest request) {
        AuthResult authResult = this.accessService.trustDevice(accessToken.substring(7),
                DeviceUtil.getDeviceDetails(request));
        ResponseCookie cookie = createCookie(authResult.refreshToken());
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(createResponse(authResult));
    }

    @PostMapping("/login")
    @WithSpan(kind = SpanKind.SERVER, value = "login controller")
    @Operation(summary = "login exisiting user")
    public ResponseEntity<AuthResponse> login(@RequestBody ExistingUserCreds user, HttpServletRequest request) {
        AuthResult authResult = this.accessService.login(user, DeviceUtil.getDeviceDetails(request));
        ResponseCookie cookie = createCookie(authResult.refreshToken());
        if (authResult.message().equals("success")) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(createResponse(authResult));
        } else if (authResult.message().equals("user blocked")) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        } else {
            return ResponseEntity.status(HttpStatus.TEMPORARY_REDIRECT)
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(createResponse(authResult));
        }
    }

    @GetMapping("/renew")
    @WithSpan(kind = SpanKind.SERVER, value = "renew-token controller")
    @Operation(summary = "renew access token given a refresh token if you have an active session")
    public ResponseEntity<AuthResponse> renewToken(HttpServletRequest request) {
        Optional<String> refreshToken = extractRefreshTokenFromCookie(request);
        if (refreshToken.isEmpty()) {
            throw new UnauthorizedAccessException("No cookie present in request");
        }
        AuthResult authResult = this.accessService.renewToken(refreshToken.get(), DeviceUtil.getDeviceDetails(request));
        return new ResponseEntity<>(createResponse(authResult),
                HttpStatus.OK);
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

    private ResponseCookie createCookie(String refreshToken) {
        ResponseCookie cookie = ResponseCookie.from(Constants.REFRESH_TOKEN, refreshToken)
                .maxAge(calculateMaxAgeFromDate(refreshTokenUtil.getExpiresAt(refreshToken)))
                .httpOnly(true)
                .sameSite("SameSite")
                .domain(cookieDomain)
                .path("/auth-api/v1/auth/renew")
                .build();
        return cookie;
    }

    private AuthResponse createResponse(AuthResult authResult) {
        return new AuthResponse(authResult.message(), authResult.accessToken());
    }

    private Optional<String> extractRefreshTokenFromCookie(HttpServletRequest request) {
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
}
