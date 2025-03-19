package com.hangout.core.auth_api.service;

import java.math.BigInteger;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.hangout.core.auth_api.dto.request.DeviceDetails;
import com.hangout.core.auth_api.dto.response.AuthResponse;
import com.hangout.core.auth_api.entity.AccessRecord;
import com.hangout.core.auth_api.entity.Action;
import com.hangout.core.auth_api.entity.Device;
import com.hangout.core.auth_api.entity.User;
import com.hangout.core.auth_api.exceptions.DeviceProfileException;
import com.hangout.core.auth_api.exceptions.JwtNotValidException;
import com.hangout.core.auth_api.exceptions.UnIndentifiedDeviceException;
import com.hangout.core.auth_api.exceptions.UnauthorizedAccessException;
import com.hangout.core.auth_api.exceptions.UserNotFoundException;
import com.hangout.core.auth_api.repository.AccessRecordRepo;
import com.hangout.core.auth_api.repository.DeviceRepo;
import com.hangout.core.auth_api.repository.UserRepo;
import com.hangout.core.auth_api.utils.DeviceUtil;
import com.hangout.core.auth_api.utils.JwtUtil;
import com.hangout.core.auth_api.utils.RefreshTokenUtil;

import io.opentelemetry.instrumentation.annotations.WithSpan;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
class RenewTokenService {
    @Autowired
    @Qualifier("accessTokenUtil")
    private JwtUtil accessTokenUtil;
    @Autowired
    @Qualifier("refreshTokenUtil")
    private RefreshTokenUtil refreshTokenUtil;
    @Autowired
    private DeviceUtil deviceUtil;
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private AccessRecordRepo accessRecordRepo;
    @Autowired
    private DeviceRepo deviceRepo;

    @WithSpan(value = "renew token service")
    @Transactional
    public AuthResponse renewToken(String refreshToken, DeviceDetails deviceDetails) {
        log.info("refreshToken: {}", refreshToken, deviceDetails);
        validateRefreshToken(refreshToken);
        String username = this.refreshTokenUtil.getUsername(refreshToken);
        UUID deviceId = this.refreshTokenUtil.getDeviceId(refreshToken);
        log.debug("from token => username: {}, deviceId: {}", username, deviceId);
        User user = findEnabledUserFromDb(username);
        log.debug("user found from db: {}", user.getUsername());
        Device device = checkIfTheDeviceIsSameAsUsedForLogin(deviceId, deviceDetails, user);
        AccessRecord latestAccess = getLatestAccessRecordAndValidateActiveSession(
                user.getUserId(), deviceId);
        String newAccessToken = generateNewAccessTokenIfExpired(latestAccess.getAccessToken(),
                latestAccess.getAccessTokenExpiryTime(), username, deviceId);
        ZonedDateTime accessTokenExpiryTime = this.accessTokenUtil.getExpiresAt(newAccessToken).toInstant()
                .atZone(ZoneOffset.UTC);
        ZonedDateTime refreshTokenExpiryTime;
        refreshToken = latestAccess.getRefreshToken();
        refreshTokenExpiryTime = latestAccess.getRefreshTokenExpiryTime();
        Action newAction;
        if (latestAccess.getAccessToken() == newAccessToken) {
            newAction = Action.PREMATURE_TOKEN_RENEW;
        } else {
            newAction = Action.RENEW_TOKEN;
        }

        AccessRecord newAccessRecord = this.accessRecordRepo.save(
                new AccessRecord(newAccessToken, accessTokenExpiryTime, refreshToken,
                        refreshTokenExpiryTime, newAction, device,
                        user));
        device.addAccessRecord(newAccessRecord);
        this.deviceRepo.save(device);
        user.addAccessRecord(newAccessRecord);
        this.userRepo.save(user);
        String resposeMessage;
        if (device.getTrusted()) {
            resposeMessage = "success";
        } else {
            resposeMessage = "untrusted device token renew";
        }
        return new AuthResponse(newAccessToken, refreshToken, user.getUserId(), resposeMessage);
    }

    @WithSpan(value = "validate refresh token")
    private Boolean validateRefreshToken(String refreshToken) {
        if (this.refreshTokenUtil.validateToken(refreshToken)) {
            return true;
        } else {
            throw new JwtNotValidException("Token provided is invalid");
        }
    }

    @WithSpan(value = "validate user is enabled in database")
    private User findEnabledUserFromDb(String username) {
        Optional<User> user = this.userRepo.findByUserName(username);
        if (user.isPresent() && user.get().isEnabled()) {
            return user.get();
        } else {
            throw new UserNotFoundException("User indicated by the token was not found");
        }
    }

    @WithSpan(value = "check the latest record of the session and verify it is an active session")
    private AccessRecord getLatestAccessRecordAndValidateActiveSession(BigInteger userId, UUID deviceId) {
        log.debug("userId: {}, deviceId: {}", userId, deviceId);
        Optional<AccessRecord> latestAccessRecord = this.accessRecordRepo.getLatestAccessRecord(userId, deviceId);
        log.debug("latest access record: {}", latestAccessRecord.get().getUserAction());
        if (latestAccessRecord.isPresent() && latestAccessRecord.get().getUserAction() != Action.LOGOUT) {
            return latestAccessRecord.get();
        } else {
            throw new UnauthorizedAccessException(
                    "No login attempt was made from this device previously. So, can not initiate a new session");
        }
    }

    @WithSpan(value = "generate new token if the previous one had expired")
    private String generateNewAccessTokenIfExpired(String accessToken, ZonedDateTime accessTokenExpiryTime,
            String username, UUID deviceId) {
        if (accessTokenExpiryTime.isBefore(ZonedDateTime.now(ZoneOffset.UTC))) {
            return this.accessTokenUtil.generateToken(username, deviceId);
        } else {
            return accessToken;
        }
    }

    @WithSpan(value = "check if the device used to renew token same as used for login")
    private Device checkIfTheDeviceIsSameAsUsedForLogin(UUID incomingDeviceId, DeviceDetails incomingDeviceDetails,
            User user) {
        // Build the device profile based on incoming details
        Device currentDevice = deviceUtil.buildDeviceProfile(incomingDeviceDetails, user);
        if (currentDevice == null) {
            throw new DeviceProfileException("Failed to build device profile");
        }

        // Fetch the existing device from the database
        Optional<Device> deviceFromDbOpt = deviceRepo.findById(incomingDeviceId);

        if (deviceFromDbOpt.isEmpty()) {
            log.warn("No matching device found in the database for ID: {}", incomingDeviceId);
            throw new UnIndentifiedDeviceException("Device being used is different from what was used to login");
        }

        Device deviceFromDb = deviceFromDbOpt.get();
        boolean isKnownDevice = !DeviceUtil.isNewDevice(deviceFromDb, currentDevice);

        log.debug("Device ID: {} | Is known device: {}", incomingDeviceId, isKnownDevice);

        if (!isKnownDevice) {
            throw new UnIndentifiedDeviceException("Device being used is different from what was used to login");
        }

        return deviceFromDb;
    }
}
