package com.hangout.core.auth_api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.hangout.core.auth_api.dto.request.PublicUserDetails;
import com.hangout.core.auth_api.dto.request.UserValidationRequest;

import io.opentelemetry.instrumentation.annotations.WithSpan;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class InternalAccessService {
    @Autowired
    private TokenValidityCheckerService tokenValidityCheckerService;

    @WithSpan(value = "check-token-validity service")
    public PublicUserDetails checkTokenValidity(UserValidationRequest validationRequest) {
        return this.tokenValidityCheckerService.checkTokenValidity(validationRequest);
    }

}
