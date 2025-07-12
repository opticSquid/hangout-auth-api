package com.hangout.core.auth_api.dto.internal;

import java.math.BigInteger;

public record AuthResult(String accessToken, String refreshToken, BigInteger userId, AuthResultStatus status) {

}
