package me.chenqiang.crypt;

public class SecureRandomError extends Error{

	/**
	 * 
	 */
	private static final long serialVersionUID = -1566259240216622046L;

	public SecureRandomError() {
		super();
	}

	public SecureRandomError(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
	}

	public SecureRandomError(String message, Throwable cause) {
		super(message, cause);
	}

	public SecureRandomError(String message) {
		super(message);
	}

	public SecureRandomError(Throwable cause) {
		super(cause);
	}
}
