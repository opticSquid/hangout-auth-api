package com.hangout.core.auth_api.controller;

import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.hangout.core.auth_api.dto.internal.AuthResult;
import com.hangout.core.auth_api.dto.request.ExistingUserCreds;
import com.hangout.core.auth_api.dto.request.NewUser;
import com.hangout.core.auth_api.dto.request.RenewToken;
import com.hangout.core.auth_api.dto.response.AuthResponse;
import com.hangout.core.auth_api.dto.response.DefaultResponse;
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
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/v1/auth/")
@Tag(name = "Public Endpoints")
@RequiredArgsConstructor
@Slf4j
public class PublicController {
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

    @PostMapping("/trust-device")
    @WithSpan(kind = SpanKind.SERVER, value = "trust-device controller")
    @Operation(summary = "update device details to trust the current device and unlock all functionalities")
    public ResponseEntity<AuthResponse> trustDevice(@RequestHeader("Authorization") String accessToken,
            HttpServletRequest request, HttpServletResponse response) {
        AuthResult authResult = this.accessService.trustDevice(accessToken.substring(7),
                DeviceUtil.getDeviceDetails(request));
        Cookie cookie = createCookie(authResult.refreshToken());
        response.addCookie(cookie);
        return new ResponseEntity<>(createResponse(authResult), HttpStatus.OK);
    }

    @PostMapping("/login")
    @WithSpan(kind = SpanKind.SERVER, value = "login controller")
    @Operation(summary = "login exisiting user")
    public ResponseEntity<AuthResponse> login(@RequestBody ExistingUserCreds user, HttpServletRequest request) {
        AuthResult authResult = this.accessService.login(user, DeviceUtil.getDeviceDetails(request));
        if (authResult.message().equals("success")) {
            return new ResponseEntity<>(createResponse(authResult), HttpStatus.OK);
        } else if (authResult.message().equals("user blocked")) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(createResponse(authResult), HttpStatus.TEMPORARY_REDIRECT);
        }
    }

    @PostMapping("/renew")
    @WithSpan(kind = SpanKind.SERVER, value = "renew-token controller")
    @Operation(summary = "renew access token given a refresh token if you have an active session")
    public ResponseEntity<AuthResponse> renewToken(@RequestBody RenewToken tokenReq, HttpServletRequest request) {
        AuthResult authResult = this.accessService.renewToken(tokenReq.token(),
                DeviceUtil.getDeviceDetails(request));
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

    private Cookie createCookie(String refreshToken) {
        Cookie cookie = new Cookie("refresh-token", refreshToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/v1/auth");
        cookie.setMaxAge(calculateMaxAgeFromDate(refreshTokenUtil.getExpiresAt(refreshToken)));
        return cookie;
    }

    private AuthResponse createResponse(AuthResult authResult) {
        return new AuthResponse(authResult.message(), authResult.accessToken());
    }
}
