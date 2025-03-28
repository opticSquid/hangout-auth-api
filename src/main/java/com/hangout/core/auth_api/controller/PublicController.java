package com.hangout.core.auth_api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.hangout.core.auth_api.dto.request.ExistingUserCreds;
import com.hangout.core.auth_api.dto.request.NewUser;
import com.hangout.core.auth_api.dto.request.RenewToken;
import com.hangout.core.auth_api.dto.response.AuthResponse;
import com.hangout.core.auth_api.dto.response.DefaultResponse;
import com.hangout.core.auth_api.service.AccessService;
import com.hangout.core.auth_api.service.UserDetailsServiceImpl;
import com.hangout.core.auth_api.utils.DeviceUtil;

import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.instrumentation.annotations.WithSpan;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/v1/public")
@Tag(name = "Public Endpoints")
@RequiredArgsConstructor
@Slf4j
public class PublicController {
    @Autowired
    private UserDetailsServiceImpl userDetailsService;
    @Autowired
    private AccessService accessService;

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
    public String verifyAccount(@RequestParam String token) {
        log.debug("token received for verification: {}", token);
        return this.userDetailsService.verifyToken(token);
    }

    @PostMapping("/login")
    @WithSpan(kind = SpanKind.SERVER, value = "login controller")
    @Operation(summary = "login exisiting user")
    public ResponseEntity<AuthResponse> login(@RequestBody ExistingUserCreds user, HttpServletRequest request) {
        AuthResponse res = this.accessService.login(user, DeviceUtil.getDeviceDetails(request));
        if (res.message().equals("success")) {
            return new ResponseEntity<>(res, HttpStatus.OK);
        } else if (res.message().equals("user blocked")) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        } else {
            return new ResponseEntity<>(res, HttpStatus.TEMPORARY_REDIRECT);
        }
    }

    @PostMapping("/renew")
    @WithSpan(kind = SpanKind.SERVER, value = "renew-token controller")
    @Operation(summary = "renew access token given a refresh token if you have an active session")
    public ResponseEntity<AuthResponse> renewToken(@RequestBody RenewToken tokenReq, HttpServletRequest request) {
        AuthResponse authResponse = this.accessService.renewToken(tokenReq.token(),
                DeviceUtil.getDeviceDetails(request));
        return new ResponseEntity<>(authResponse,
                HttpStatus.OK);
    }
}
