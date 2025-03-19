package com.hangout.core.auth_api.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.hangout.core.auth_api.dto.request.DeviceDetails;
import com.hangout.core.auth_api.dto.request.ExistingUserCreds;
import com.hangout.core.auth_api.dto.response.AuthResponse;
import com.hangout.core.auth_api.dto.response.DefaultResponse;

import io.opentelemetry.instrumentation.annotations.WithSpan;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AccessService {
    @Autowired
    private LoginService loginService;
    @Autowired
    private RenewTokenService renewTokenService;
    @Autowired
    private LogoutService logoutService;
    @Autowired
    private TrustDeviceService trustDeviceService;

    @WithSpan(value = "login service - wrapper service")
    @Transactional
    public AuthResponse login(ExistingUserCreds userCreds, DeviceDetails deviceDetails) {
        return this.loginService.login(userCreds, deviceDetails);
    }

    @WithSpan(value = "renew-token service - wrapper service")
    @Transactional
    public AuthResponse renewToken(String refreshToken, DeviceDetails deviceDetails) {
        return this.renewTokenService.renewToken(refreshToken, deviceDetails);

    }

    @WithSpan(value = "logout service - wrapper service")
    public DefaultResponse logout(String accessToken, DeviceDetails deviceDetails) {
        return this.logoutService.logout(accessToken, deviceDetails);
    }

    @WithSpan(value = "trust-device service - wrapper service")
    public AuthResponse trustDevice(String accessToken, DeviceDetails deviceDetails) {
        return this.trustDeviceService.trustDevice(accessToken, deviceDetails);
    }
}
