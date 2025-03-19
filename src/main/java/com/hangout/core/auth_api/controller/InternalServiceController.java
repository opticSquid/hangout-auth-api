package com.hangout.core.auth_api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hangout.core.auth_api.dto.request.PublicUserDetails;
import com.hangout.core.auth_api.dto.request.UserValidationRequest;
import com.hangout.core.auth_api.service.InternalAccessService;

import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.instrumentation.annotations.WithSpan;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/v1/internal")
@Tag(name = "Internal Endpoints")
@Slf4j
public class InternalServiceController {
    @Autowired
    private InternalAccessService accessService;

    @PostMapping("/validate")
    @WithSpan(kind = SpanKind.SERVER, value = "validate-token controller")
    @Operation(summary = "check validity of access token")
    public ResponseEntity<PublicUserDetails> validateAccessToken(@RequestBody UserValidationRequest validationRequest) {
        return new ResponseEntity<>(
                this.accessService.checkTokenValidity(validationRequest),
                HttpStatus.OK);
    }
}
