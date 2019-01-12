package me.chenqiang.crypt;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 与SecureRandom有关的操作
 * 
 * @author CHEN Qiang
 *
 */
public class SecureRandomFunctions {
	private SecureRandomFunctions() {}
	public static class SecureRandomException extends Error{
		private static final long serialVersionUID = 6573746562529758358L;

		public SecureRandomException() {
			super();
		}

		public SecureRandomException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
			super(message, cause, enableSuppression, writableStackTrace);
		}

		public SecureRandomException(String message, Throwable cause) {
			super(message, cause);
		}

		public SecureRandomException(String message) {
			super(message);
		}

		public SecureRandomException(Throwable cause) {
			super(cause);
		}
	}
	
	public static final SecureRandom SHARED_STATIC_RND = getStrongRandom();
	
	public static final SecureRandom getStrongRandom() {
		try {
			return SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new SecureRandomException(e);
		}
	}

	
	/**
	 * 生成随机字节，常用于生成初始向量。
	 * 
	 * @param rnd 
	 * @param size 随机字节长度（bytes）
	 * @return
	 */
	public static byte [] generateRandomBytes(Random rnd, int size) {
		byte [] data = new byte[size];
		rnd.nextBytes(data);
		return data;		
	}	
	
	public static final int MAX_RESEED_COUNT = 10000; 
	public static final AtomicInteger RESEED_COUNTDOWN = new AtomicInteger(MAX_RESEED_COUNT); 
	/**
	 * 生成随机字节，常用于生成初始向量。
	 * 
	 * @param rnd 
	 * @param size 随机字节长度（bytes）
	 * @return
	 */
	public static byte [] generateRandomBytes(int size) {
		byte [] data = new byte[size];
		SHARED_STATIC_RND.nextBytes(data);
		
		RESEED_COUNTDOWN.decrementAndGet();
		if(RESEED_COUNTDOWN.compareAndSet(0, MAX_RESEED_COUNT)) {
			SHARED_STATIC_RND.reseed();
		}		
		return data;		
	}	
}
