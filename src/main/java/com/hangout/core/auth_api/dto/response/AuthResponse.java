package com.hangout.core.auth_api.dto.response;

import java.math.BigInteger;

public record AuthResponse(String accessToken, String refreshToken, BigInteger userId, String message) {

}
