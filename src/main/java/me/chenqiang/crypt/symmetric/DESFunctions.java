package me.chenqiang.crypt.symmetric;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import me.chenqiang.crypt.SecureRandomFunctions;

/**
 * DES和3DES加密解密的操作
 * 
 * @author Lancelot
 *
 */
public class DESFunctions implements SymmetricFunctions{
	private DESFunctions() {
	}
	
	public static final String DES = SymmetricConsts.DES;
	public static final String DESEDE = SymmetricConsts.DESEDE;
	

	public static final int DES_BLOCK_SIZE = 8;
	public static final int TRIPLE_DES_2_KEY_BITS = 16 * 8;
	public static final int TRIPLE_DES_3_KEY_BITS = 24 * 8;
	
	private static final SecureRandom KEY_RND = SecureRandomFunctions.getStrongRandom();
	private static final SecureRandom IV_RND = new SecureRandom();
	
	public static SecretKey generateDesKey() 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return SymmetricFunctions.generateSecretKey(KEY_RND, SymmetricConsts.DES, DES_BLOCK_SIZE);
	}
	
	public static SecretKey generate3DesKey16() 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return SymmetricFunctions.generateSecretKey(KEY_RND, DESEDE, TRIPLE_DES_2_KEY_BITS);
	}
	
	public static SecretKey generate3DesKey24() 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return SymmetricFunctions.generateSecretKey(KEY_RND, DESEDE, TRIPLE_DES_3_KEY_BITS);
	}
	
	public static byte [] generateDesIv() {
		return SecureRandomFunctions.generateRandomBytes(IV_RND, DES_BLOCK_SIZE);
	}	
}
