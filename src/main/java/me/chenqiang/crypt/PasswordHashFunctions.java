package me.chenqiang.crypt;

import java.security.GeneralSecurityException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 
 * @author CHEN Qiang
 *
 */
public class PasswordHashFunctions {
	private PasswordHashFunctions() {}
	public static final String PBKDF2_WITH_HMAC_SHA1 = "PBKDF2WithHmacSHA1";
	public static final String PBKDF2_WITH_HMAC_SHA224 = "PBKDF2WithHmacSHA224";
	public static final String PBKDF2_WITH_HMAC_SHA256 = "PBKDF2WithHmacSHA256";
	public static final String PBKDF2_WITH_HMAC_SHA384 = "PBKDF2WithHmacSHA384";
	public static final String PBKDF2_WITH_HMAC_SHA512 = "PBKDF2WithHmacSHA512";
	public static final String PBKDF2_WITH_HMAC_SHA3224 = "PBKDF2WithHmacSHA3-224";
	public static final String PBKDF2_WITH_HMAC_SHA3256 = "PBKDF2WithHmacSHA3-256";
	public static final String PBKDF2_WITH_HMAC_SHA3384 = "PBKDF2WithHmacSHA3-384";
	public static final String PBKDF2_WITH_HMAC_SHA3512 = "PBKDF2WithHmacSHA3-512";
	
	/**
	 * NIST recommended minimum iterations for iteration count.
	 * {@link https://cryptosense.com/blog/parameter-choice-for-pbkdf2/}
	 */
	public static final int RECOMMENDED_MINIMUM_ITERATIONS = 10000;
		
	public static byte [] derivePbkdf2Key(String algorithm, 
			String password, byte [] salt, int iterationCount, int keyBitSize) 
			throws GeneralSecurityException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
	    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyBitSize);
	    SecretKey key = factory.generateSecret(keySpec);
	    return key.getEncoded();
	}
}
