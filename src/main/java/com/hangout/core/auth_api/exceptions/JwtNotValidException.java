package com.hangout.core.auth_api.exceptions;

public class JwtNotValidException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 2263536034769105506L;
	private String message;

	public JwtNotValidException() {
		super();
	}

	public JwtNotValidException(String message) {
		super(message);
		this.message = message;
	}

	public String getMessage() {
		return message;
	}
}
