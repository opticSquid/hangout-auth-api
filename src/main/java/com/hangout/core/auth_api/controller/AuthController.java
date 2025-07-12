package com.hangout.core.auth_api.controller;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.hangout.core.auth_api.dto.internal.AuthResult;
import com.hangout.core.auth_api.dto.internal.AuthResultStatus;
import com.hangout.core.auth_api.dto.request.ExistingUserCreds;
import com.hangout.core.auth_api.dto.request.NewUser;
import com.hangout.core.auth_api.dto.response.AuthResponse;
import com.hangout.core.auth_api.dto.response.DefaultResponse;
import com.hangout.core.auth_api.exceptions.UnauthorizedAccessException;
import com.hangout.core.auth_api.service.AccessService;
import com.hangout.core.auth_api.service.UserDetailsServiceImpl;
import com.hangout.core.auth_api.utils.CookieUtil;
import com.hangout.core.auth_api.utils.DeviceUtil;
import com.hangout.core.auth_api.utils.RefreshTokenUtil;

import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.instrumentation.annotations.WithSpan;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/v1/auth/")
@Tag(name = "Public Endpoints")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private AccessService accessService;

    @Autowired
    @Qualifier("refreshTokenUtil")
    private RefreshTokenUtil refreshTokenUtil;

    @Autowired
    private CookieUtil cookieUtil;

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

    @PostMapping("/login")
    @WithSpan(kind = SpanKind.SERVER, value = "login controller")
    @Operation(summary = "login exisiting user")
    public ResponseEntity<AuthResponse> login(@RequestBody ExistingUserCreds user, HttpServletRequest request) {
        AuthResult authResult = this.accessService.login(user, DeviceUtil.getDeviceDetails(request));
        ResponseCookie cookie = cookieUtil.createCookie(authResult.refreshToken());
        if (authResult.status().equals(AuthResultStatus.LONG_TERM_ACCESS)
                || authResult.status().equals(AuthResultStatus.SHORT_TERM_ACCESS)) {
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(createResponse(authResult));
        } else {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
    }

    @GetMapping("/renew")
    @WithSpan(kind = SpanKind.SERVER, value = "renew-token controller")
    @Operation(summary = "renew access token given a refresh token if you have an active session")
    public ResponseEntity<AuthResponse> renewToken(HttpServletRequest request) {
        Optional<String> refreshToken = cookieUtil.extractRefreshTokenFromCookie(request);
        if (refreshToken.isEmpty()) {
            throw new UnauthorizedAccessException("No cookie present in request");
        }
        AuthResult authResult = this.accessService.renewToken(refreshToken.get(), DeviceUtil.getDeviceDetails(request));
        return new ResponseEntity<>(createResponse(authResult),
                HttpStatus.OK);
    }

    private AuthResponse createResponse(AuthResult authResult) {
        return new AuthResponse(authResult.status().label, authResult.accessToken(),
                authResult.status().equals(AuthResultStatus.LONG_TERM_ACCESS));
    }
}
