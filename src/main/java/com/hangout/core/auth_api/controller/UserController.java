package com.hangout.core.auth_api.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hangout.core.auth_api.dto.internal.AuthResult;
import com.hangout.core.auth_api.dto.response.AuthResponse;
import com.hangout.core.auth_api.dto.response.DefaultResponse;
import com.hangout.core.auth_api.service.AccessService;
import com.hangout.core.auth_api.service.UserDetailsServiceImpl;
import com.hangout.core.auth_api.utils.CookieUtil;
import com.hangout.core.auth_api.utils.DeviceUtil;

import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.instrumentation.annotations.WithSpan;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/v1/user")
@Tag(name = "Protected Endpoints")
@Slf4j
public class UserController {
	@Autowired
	private UserDetailsServiceImpl userDetailsService;
	@Autowired
	private AccessService accessService;
	@Autowired
	private CookieUtil cookieUtil;

	@GetMapping("/trust-device")
	@WithSpan(kind = SpanKind.SERVER, value = "trust-device controller")
	@Operation(summary = "update device details to trust the current device and unlock all functionalities")
	public ResponseEntity<AuthResponse> trustDevice(@RequestHeader("Authorization") String accessToken,
			HttpServletRequest request) {
		AuthResult authResult = this.accessService.trustDevice(accessToken.substring(7),
				DeviceUtil.getDeviceDetails(request));
		ResponseCookie cookie = cookieUtil.CreateCookie(authResult.refreshToken());
		return ResponseEntity.ok()
				.header(HttpHeaders.SET_COOKIE, cookie.toString())
				.body(new AuthResponse(authResult.message(), authResult.accessToken()));
	}

	@DeleteMapping("/logout")
	@WithSpan(kind = SpanKind.SERVER, value = "logout controller")
	@Operation(summary = "logout of an active session")
	public ResponseEntity<DefaultResponse> logout(@RequestHeader("Authorization") String accessToken,
			HttpServletRequest req) {
		return new ResponseEntity<>(
				this.accessService.logout(accessToken.substring(7), DeviceUtil.getDeviceDetails(req)),
				HttpStatus.OK);
	}

	@DeleteMapping
	@WithSpan(kind = SpanKind.SERVER, value = "delete-account controller")
	@Operation(summary = "remove user account permanently")
	public ResponseEntity<DefaultResponse> deleteUser() {
		try {
			String userName = getAuthenticatedUser().getName();
			this.userDetailsService.deleteUser(userName);
			return new ResponseEntity<>(new DefaultResponse("User with username: " + userName + " deleted"),
					HttpStatus.OK);
		} catch (Exception e) {
			log.error("Exception: {}", e.getCause());
			return new ResponseEntity<>(new DefaultResponse("User could not be deleted"), HttpStatus.BAD_REQUEST);
		}
	}

	private Authentication getAuthenticatedUser() {
		return SecurityContextHolder.getContext().getAuthentication();
	}
}
