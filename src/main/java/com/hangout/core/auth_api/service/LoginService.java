package com.hangout.core.auth_api.service;

import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.hangout.core.auth_api.dto.request.DeviceDetails;
import com.hangout.core.auth_api.dto.request.ExistingUserCreds;
import com.hangout.core.auth_api.dto.response.AuthResponse;
import com.hangout.core.auth_api.entity.AccessRecord;
import com.hangout.core.auth_api.entity.Action;
import com.hangout.core.auth_api.entity.Device;
import com.hangout.core.auth_api.entity.User;
import com.hangout.core.auth_api.exceptions.DeviceProfileException;
import com.hangout.core.auth_api.exceptions.UnIndentifiedDeviceException;
import com.hangout.core.auth_api.exceptions.UnauthorizedAccessException;
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
class LoginService {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    @Qualifier("accessTokenUtil")
    private JwtUtil accessTokenUtil;
    @Autowired
    @Qualifier("refreshTokenUtil")
    private RefreshTokenUtil refreshTokenUtil;
    @Autowired
    private UserRepo userRepo;
    @Autowired
    private AccessRecordRepo accessRecordRepo;
    @Autowired
    private DeviceRepo deviceRepo;
    @Autowired
    private DeviceUtil deviceUtil;

    @WithSpan(value = "login service")
    @Transactional
    public AuthResponse login(ExistingUserCreds userCreds, DeviceDetails deviceDetails) {
        log.debug("authenticating user");
        Authentication auth = autheticateUser(userCreds);
        String username = auth.getName();
        log.debug("authenticated user : {}", username);
        User user = this.userRepo.findByUserName(username).get();
        log.debug("user id from db: {}", user.getUserId());
        // if user is not enabled, do not allow login
        if (!user.isEnabled()) {
            return new AuthResponse(null, null, null, "user not enabled");
        } else {
            // user is enabled
            // check if the current device is a trusted device or not
            try {
                Device device = getUserDevice(deviceDetails, user);
                if (device.getTrusted()) {
                    // get the last login/logout attempt by the user in current device
                    Optional<AccessRecord> session = this.accessRecordRepo.getLastEntryRecord(user.getUserId(),
                            device.getDeviceId());
                    // user had logged in before in the current device and marked it as a trusted
                    // device
                    return userLoggingInToTrustedDevice(session.get(), device, user);
                } else {
                    return userLoggingInAnUntrustedDevice(device, user);
                }
            } catch (UnIndentifiedDeviceException ex) {
                log.info("user logging in a new device");
                // create a new device object for saving
                Device newUntrustedDevice = this.deviceUtil.buildDeviceProfile(deviceDetails, user);
                return userLoggingInAnUnIdentifiedDevice(newUntrustedDevice, user);
            }
        }
    }

    @WithSpan(value = "authenticate user")
    private Authentication autheticateUser(ExistingUserCreds userCreds) {
        return authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(userCreds.username(), userCreds.password()));
    }

    @WithSpan(value = "check current device against user's known devices")
    private Device getUserDevice(DeviceDetails deviceDetails, User user) {
        // Build the current device profile
        Device currentDevice = deviceUtil.buildDeviceProfile(deviceDetails, user);
        if (currentDevice == null) {
            throw new DeviceProfileException("Failed to build device profile");
        }

        // Fetch similar devices from the database
        List<Device> similarDevices = deviceRepo.findAllMatchingDevices(
                deviceDetails.os(), deviceDetails.screenWidth(), deviceDetails.screenHeight(),
                deviceDetails.userAgent(), currentDevice.getContinent(),
                currentDevice.getCountry(), user.getUserId());

        // If no similar devices are found, it's an unidentified device
        if (similarDevices.isEmpty()) {
            throw new UnIndentifiedDeviceException("Device was never used by user");
        }

        // Check if the current device is already recognized
        Optional<Device> matchedDevice = similarDevices.stream()
                .filter(dbDevice -> !DeviceUtil.isNewDevice(dbDevice, currentDevice))
                .findFirst();

        if (matchedDevice.isPresent()) {
            // Update ISP if necessary and save the device
            Device deviceFromDb = matchedDevice.get();
            if (!deviceFromDb.getIsp().equals(currentDevice.getIsp())) {
                deviceFromDb.setIsp(currentDevice.getIsp());
                deviceRepo.save(deviceFromDb);
            }
            return deviceFromDb;
        }

        // If no match was found, it's an unidentified device
        throw new UnIndentifiedDeviceException("Device was never used by user");
    }

    @WithSpan(value = "user logging in to trusted device")
    private AuthResponse userLoggingInToTrustedDevice(AccessRecord session,
            Device trustedDevice, User user) {
        Action action = session.getUserAction();
        ZonedDateTime refreshTokenExpiryTime = session.getRefreshTokenExpiryTime();
        if (action.equals(Action.LOGIN)
                && refreshTokenExpiryTime.isBefore(ZonedDateTime.now(ZoneOffset.UTC))) {
            log.info("user is logging in after a long time, the past active session's refresh token has expired");
            return loginAfterRefreshTokenExpired(trustedDevice, user);
        } else if (action.equals(Action.LOGIN)) {
            log.info("User already has a active session in current device");
            throw new UnauthorizedAccessException(
                    "User already has an active session is this device. Either switch to the existing session or logout of the existing session");
        } else {
            return loginAfterUserManuallyLoggedOut(trustedDevice, user);
        }
    }

    @WithSpan(value = "user logging in after previous refresh token expired")
    private AuthResponse loginAfterRefreshTokenExpired(Device trustedDevice, User user) {
        String accessJwt = this.accessTokenUtil.generateToken(user.getUsername(), trustedDevice.getDeviceId());
        Date iatAccessToken = this.accessTokenUtil.getExpiresAt(accessJwt);
        String refreshJwt = this.refreshTokenUtil.generateToken(user.getUsername(), trustedDevice.getDeviceId());
        Date iatRefreshToken = this.refreshTokenUtil.getExpiresAt(refreshJwt);
        AccessRecord accessRecord = this.accessRecordRepo.save(
                new AccessRecord(accessJwt, iatAccessToken, refreshJwt, iatRefreshToken, Action.LOGIN,
                        trustedDevice, user));
        user.addAccessRecord(accessRecord);
        trustedDevice.addAccessRecord(accessRecord);
        this.deviceRepo.save(trustedDevice);
        this.userRepo.save(user);
        return new AuthResponse(accessJwt, refreshJwt, user.getUserId(), "success");
    }

    @WithSpan(value = "user logging in after manual logout")
    private AuthResponse loginAfterUserManuallyLoggedOut(
            Device trustedDevice, User user) {
        log.info("user had previously logged out of a session in this current device");
        String accessJwt = this.accessTokenUtil.generateToken(user.getUsername(), trustedDevice.getDeviceId());
        Date iatAccessToken = this.accessTokenUtil.getExpiresAt(accessJwt);
        String refreshJwt = this.refreshTokenUtil.generateToken(user.getUsername(), trustedDevice.getDeviceId());
        Date iatRefreshToken = this.refreshTokenUtil.getExpiresAt(refreshJwt);
        AccessRecord accessRecord = this.accessRecordRepo.save(
                new AccessRecord(accessJwt, iatAccessToken, refreshJwt, iatRefreshToken, Action.LOGIN,
                        trustedDevice, user));
        user.addAccessRecord(accessRecord);
        trustedDevice.addAccessRecord(accessRecord);
        this.deviceRepo.save(trustedDevice);
        this.userRepo.save(user);
        return new AuthResponse(accessJwt, refreshJwt, user.getUserId(), "success");
    }

    @WithSpan(value = "user logging in an untrusted device")
    private AuthResponse userLoggingInAnUntrustedDevice(Device untrustedDevice, User user) {
        String accessJwt = this.accessTokenUtil.generateToken(user.getUsername(), untrustedDevice.getDeviceId());
        Date iatAccessToken = this.accessTokenUtil.getExpiresAt(accessJwt);
        String shortTermRefreshJwt = this.refreshTokenUtil.generateTokenShortTerm(user.getUsername(),
                untrustedDevice.getDeviceId());
        Date iatRefreshToken = this.refreshTokenUtil.getExpiresAt(shortTermRefreshJwt);
        AccessRecord accessRecord = new AccessRecord(accessJwt, iatAccessToken, shortTermRefreshJwt, iatRefreshToken,
                Action.LOGIN,
                untrustedDevice, user);
        log.debug("new access record: {}", accessRecord);
        accessRecord = this.accessRecordRepo.save(accessRecord);
        user.addAccessRecord(accessRecord);
        untrustedDevice.addAccessRecord(accessRecord);
        this.deviceRepo.save(untrustedDevice);
        this.userRepo.save(user);
        return new AuthResponse(accessJwt, shortTermRefreshJwt, user.getUserId(), "untrusted device login");
    }

    @WithSpan(value = "user logging-in in a new device")
    private AuthResponse userLoggingInAnUnIdentifiedDevice(Device unIdentifiedDevice, User user) {
        // saving new Device
        unIdentifiedDevice = this.deviceRepo.save(unIdentifiedDevice);
        String accessJwt = this.accessTokenUtil.generateToken(user.getUsername(), unIdentifiedDevice.getDeviceId());
        Date iatAccessToken = this.accessTokenUtil.getExpiresAt(accessJwt);
        String shortTermRefreshJwt = this.refreshTokenUtil.generateTokenShortTerm(user.getUsername(),
                unIdentifiedDevice.getDeviceId());
        Date iatRefreshToken = this.refreshTokenUtil.getExpiresAt(shortTermRefreshJwt);
        AccessRecord accessRecord = new AccessRecord(accessJwt, iatAccessToken, shortTermRefreshJwt, iatRefreshToken,
                Action.LOGIN,
                unIdentifiedDevice, user);
        log.debug("new access record: {}", accessRecord);
        accessRecord = this.accessRecordRepo.save(accessRecord);
        user.addAccessRecord(accessRecord);
        unIdentifiedDevice.addAccessRecord(accessRecord);
        this.deviceRepo.save(unIdentifiedDevice);
        this.userRepo.save(user);
        return new AuthResponse(accessJwt, shortTermRefreshJwt, user.getUserId(), "untrusted device login");
    }
}
