package com.hangout.core.auth_api.service;

import java.math.BigInteger;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.hangout.core.auth_api.dto.request.PublicUserDetails;
import com.hangout.core.auth_api.dto.request.UserValidationRequest;
import com.hangout.core.auth_api.entity.Device;
import com.hangout.core.auth_api.entity.User;
import com.hangout.core.auth_api.exceptions.JwtNotValidException;
import com.hangout.core.auth_api.exceptions.UnIndentifiedDeviceException;
import com.hangout.core.auth_api.exceptions.UserNotFoundException;
import com.hangout.core.auth_api.repository.DeviceRepo;
import com.hangout.core.auth_api.repository.UserRepo;
import com.hangout.core.auth_api.utils.JwtUtil;

import io.opentelemetry.instrumentation.annotations.WithSpan;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
class TokenValidityCheckerService {
    @Autowired
    @Qualifier("accessTokenUtil")
    private JwtUtil accessTokenUtil;
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private DeviceRepo deviceRepo;

    @WithSpan(value = "check the validity of the token")
    public PublicUserDetails checkTokenValidity(UserValidationRequest validationRequest) {
        String acessToken = validateAndExtractAccessToken(validationRequest.accessToken());
        String username = this.accessTokenUtil.getUsername(acessToken);
        UUID deviceId = this.accessTokenUtil.getDeviceId(acessToken);
        User user = this.findEnabledUser(username);
        Device device = findDevice(user.getUserId(), deviceId);
        return new PublicUserDetails(user.getUserId(), user.getRole(), device.getTrusted());

    }

    @WithSpan(value = "extract access token from header and validate it")
    private String validateAndExtractAccessToken(String accessToken) {
        if (accessToken != null && accessToken.startsWith("Bearer ")) {
            String jwt = accessToken.substring(7);
            if (this.accessTokenUtil.validateToken(jwt)) {
                return jwt;
            } else {
                throw new JwtNotValidException("The incoming access token for token validation is expired");
            }
        } else {
            throw new JwtNotValidException("Access token is not valid for the user incoming for token validation");
        }
    }

    @WithSpan(value = "check if the user is enabled in database")
    private User findEnabledUser(String username) {
        Optional<User> user = this.userRepo.findByUserName(username);
        if (user.isPresent() && user.get().isEnabled() == true) {
            return user.get();
        } else {
            throw new UserNotFoundException(
                    "The incoming user for token validation is either not found in database or is not enabled");
        }
    }

    @WithSpan(value = "check if the incoming device has been used by the user or not")
    private Device findDevice(BigInteger userId, UUID deviceId) {
        Optional<Device> deviceFromDb = this.deviceRepo.validateDeviceOwnership(deviceId, userId);
        if (deviceFromDb.isPresent()) {
            return deviceFromDb.get();
        } else {
            throw new UnIndentifiedDeviceException("the incoming device does not belong to the incoming user");
        }
    }
}
