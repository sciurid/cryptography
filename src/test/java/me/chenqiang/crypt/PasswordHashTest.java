package me.chenqiang.crypt;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class PasswordHashTest {
	public static final SecureRandom RND = new SecureRandom();
	@Before
	public void init() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	public void compareSunJCEWithdBC() throws GeneralSecurityException {
		String password = "xrS7AJk+V6L8J?B%";
		SecureRandom rnd = new SecureRandom();
		int saltLength = 16;
		int keyBitSize = 256;
		int iterationCount = 10000;
		
		byte[] salt = new byte[saltLength];
		rnd.nextBytes(salt);
		
		SecretKeyFactory factorySun = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", "SunJCE");
	    KeySpec keyspecSun = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyBitSize);
	    SecretKey keySun = factorySun.generateSecret(keyspecSun);
	    System.out.println(keySun.getClass().getName());
	    System.out.println(Hex.toHexString(keySun.getEncoded()));
	    
	    SecretKeyFactory factoryBC = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1", BouncyCastleProvider.PROVIDER_NAME);
	    KeySpec keyspecBC = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyBitSize);
	    SecretKey keyBC = factoryBC.generateSecret(keyspecBC);
	    System.out.println(keyBC.getClass().getName());
	    System.out.println(Hex.toHexString(keyBC.getEncoded()));
	    
	    Assert.assertArrayEquals(keySun.getEncoded(), keyBC.getEncoded());
	}
	
	@Test
	public void testSupportedPBKDF2() {
		String password = "xrS7AJk+V6L8J?B%";
		SecureRandom rnd = new SecureRandom();
		
		int saltLength = 16;
		int keyBitSize = 256;
		int iterationCount = 100;
		
		byte[] salt = new byte[saltLength];
		rnd.nextBytes(salt);
		
		String [] algorithms = {
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA1,
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA224,
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA256,
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA384,
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA512,
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA3224,
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA3256,
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA3384,
				PasswordHashFunctions.PBKDF2_WITH_HMAC_SHA3512};
		for(String algorithm : algorithms) {
			System.out.println(algorithm);
			try {
				SecretKeyFactory factoryBC = SecretKeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
			    KeySpec keyspecBC = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyBitSize);
			    SecretKey keyBC = factoryBC.generateSecret(keyspecBC);
			    System.out.println(keyBC.getClass().getName());
		    }
			catch(GeneralSecurityException e) {
				System.out.println(e);
			}
			
			try {
				SecretKeyFactory factoryBC = SecretKeyFactory.getInstance(algorithm, "SunJCE");
			    KeySpec keyspecBC = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keyBitSize);
			    SecretKey keyBC = factoryBC.generateSecret(keyspecBC);
			    System.out.println(keyBC.getClass().getName());
		    }
			catch(GeneralSecurityException e) {
				System.out.println(e);
			}
			
		}
	}
}
