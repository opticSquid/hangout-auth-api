package com.hangout.core.auth_api.service;

import java.math.BigInteger;
import java.util.Date;
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
import com.hangout.core.auth_api.exceptions.AlreadyTrustedDeviceException;
import com.hangout.core.auth_api.exceptions.DeviceProfileException;
import com.hangout.core.auth_api.exceptions.UnIndentifiedDeviceException;
import com.hangout.core.auth_api.exceptions.UserNotFoundException;
import com.hangout.core.auth_api.repository.AccessRecordRepo;
import com.hangout.core.auth_api.repository.DeviceRepo;
import com.hangout.core.auth_api.repository.UserRepo;
import com.hangout.core.auth_api.utils.DeviceUtil;
import com.hangout.core.auth_api.utils.JwtUtil;

import io.micrometer.observation.annotation.Observed;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
class TrustDeviceService {
    @Autowired
    @Qualifier("accessTokenUtil")
    private JwtUtil accessTokenUtil;
    @Autowired
    @Qualifier("refreshTokenUtil")
    private JwtUtil refreshTokenUtil;
    @Autowired
    private DeviceUtil deviceUtil;
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private DeviceRepo deviceRepo;
    @Autowired
    private AccessRecordRepo accessRecordRepo;

    @Transactional
    @Observed(name = "trust-device", contextualName = "trust-device-service")
    public AuthResponse trustDevice(String accessToken, DeviceDetails deviceDetails) {
        log.info("accessToken: {}", accessToken, deviceDetails);
        String username = this.accessTokenUtil.getUsername(accessToken);
        UUID deviceId = this.accessTokenUtil.getDeviceId(accessToken);
        User user = findEnabledUserFromDb(username);
        Device device = checkIfTheDeviceIsSameAsUsedForLogin(deviceId, deviceDetails, user);
        if (device.isTrusted()) {
            throw new AlreadyTrustedDeviceException("Device is already trusted by the user.");
        } else {
            AuthResponse issuedTokens = issueLongTermTokens(user.getUsername(), deviceId, user.getUserId());
            Date accessTokenExpiryTime = this.accessTokenUtil.getExpiresAt(issuedTokens.accessToken());
            Date refreshTokenExpiryTime = this.refreshTokenUtil.getExpiresAt(issuedTokens.refreshToken());
            AccessRecord accessRecord = this.accessRecordRepo
                    .save(new AccessRecord(issuedTokens.accessToken(), accessTokenExpiryTime,
                            issuedTokens.refreshToken(),
                            refreshTokenExpiryTime, Action.TRUSTED_SESSION_START, device,
                            user));
            device.trustDevice();
            device.addAccessRecord(accessRecord);
            this.deviceRepo.save(device);
            user.addAccessRecord(accessRecord);
            this.userRepo.save(user);
            return issuedTokens;
        }
    }

    private User findEnabledUserFromDb(String username) {
        Optional<User> user = this.userRepo.findByUserName(username);
        if (user.isPresent() && user.get().isEnabled()) {
            return user.get();
        } else {
            throw new UserNotFoundException("User indicated by the token was not found");
        }
    }

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

    private AuthResponse issueLongTermTokens(String username, UUID deviceId, BigInteger userId) {
        String accessToken = this.accessTokenUtil.generateToken(username, deviceId);
        String refreshToken = this.refreshTokenUtil.generateToken(username, deviceId);
        return new AuthResponse(accessToken, refreshToken, userId, "success");
    }
}
