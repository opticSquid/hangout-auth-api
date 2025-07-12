package com.hangout.core.auth_api.exceptions.handlers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.hangout.core.auth_api.exceptions.UnIndentifiedDeviceException;
import com.hangout.core.auth_api.exceptions.AlreadyTrustedDeviceException;
import com.hangout.core.auth_api.exceptions.JwtNotValidException;
import com.hangout.core.auth_api.exceptions.UnauthorizedAccessException;
import com.hangout.core.auth_api.exceptions.UserNotFoundException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {
	@ExceptionHandler(UserNotFoundException.class)
	public ProblemDetail exceptionHandler(UserNotFoundException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
		problem.setTitle("Given user/s not found");
		return problem;
	}

	@ExceptionHandler(JwtNotValidException.class)
	public ProblemDetail exceptionHandler(JwtNotValidException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
		problem.setTitle("Token is invalid");
		return problem;
	}

	@ExceptionHandler(ExpiredJwtException.class)
	public ProblemDetail exceptionHandler(ExpiredJwtException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
		problem.setTitle("Token has expired");
		return problem;
	}

	@ExceptionHandler(UnauthorizedAccessException.class)
	public ProblemDetail exceptionHandler(UnauthorizedAccessException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
		problem.setTitle("Access Denied");
		return problem;
	}

	@ExceptionHandler(UnIndentifiedDeviceException.class)
	public ProblemDetail exceptionHandler(UnIndentifiedDeviceException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
		problem.setTitle("Untrusted Device");
		return problem;
	}

	@ExceptionHandler(AlreadyTrustedDeviceException.class)
	public ProblemDetail exceptionHandler(AlreadyTrustedDeviceException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
		problem.setTitle("Already Trusted Device");
		return problem;
	}

	// Spring generated exceptions

	@ExceptionHandler(BadCredentialsException.class)
	public ProblemDetail exceptionHandler(BadCredentialsException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Username or password is wrong");
		problem.setTitle("Bad Credentials");
		return problem;
	}

	@ExceptionHandler(MalformedJwtException.class)
	public ProblemDetail exceptionHandler(MalformedJwtException ex) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, ex.getMessage());
		problem.setTitle("Token is invalid");
		return problem;
	}

}