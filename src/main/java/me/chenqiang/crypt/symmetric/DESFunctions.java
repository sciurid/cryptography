package me.chenqiang.crypt.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DESFunctions implements SymmetricFunctions{
	private DESFunctions() {
	}

	public static final String DES = "DES";
	public static final String DESEDE = "DESede";
	public static final int DES_BLOCK_SIZE = 8;
	public static final int TRIPLE_DES_2_KEY_BITS = 16 * 8;
	public static final int TRIPLE_DES_3_KEY_BITS = 24 * 8;
	
	private static final SecureRandom KEY_RND;
	private static final SecureRandom IV_RND;
	static {
		try {
			KEY_RND = SecureRandom.getInstanceStrong();
			IV_RND  = new SecureRandom();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("NO STRONG SECURE RANDOM", e);
		}
	}
	
	public static SecretKey generateDesKey() 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kgen = KeyGenerator.getInstance(DES, BouncyCastleProvider.PROVIDER_NAME);
		kgen.init(DES_BLOCK_SIZE, KEY_RND);
		return kgen.generateKey();
	}
	
	public static SecretKey generate3DesKey16() 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kgen = KeyGenerator.getInstance(DESEDE, BouncyCastleProvider.PROVIDER_NAME);
		kgen.init(TRIPLE_DES_2_KEY_BITS, KEY_RND);
		return kgen.generateKey();
	}
	
	public static SecretKey generate3DesKey24() 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kgen = KeyGenerator.getInstance(DESEDE, BouncyCastleProvider.PROVIDER_NAME);
		kgen.init(TRIPLE_DES_3_KEY_BITS, KEY_RND);
		return kgen.generateKey();
	}
	
	public static byte [] generateDesIv() {
		return SymmetricFunctions.generateRandomBytes(IV_RND, DES_BLOCK_SIZE);
	}	
}
