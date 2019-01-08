package me.chenqiang.crypt;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ECCFunctions {
	private ECCFunctions() {}
	
	public static final String EC = "EC";
	public static final String ECIES = "ECIES";
	
	public static final String SHA1_ECDSA = "SHA1withECDSA";
	public static final String NONE_ECDSA = "NONEwithECDSA";
	public static final String SHA224_ECDSA = "SHA224withECDSA";
	public static final String SHA256_ECDSA = "SHA256withECDSA";
	public static final String SHA384_ECDSA = "SHA384withECDSA";
	public static final String SHA512_ECDSA = "SHA512withECDSA";
	
	public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance(EC, new BouncyCastleProvider());
		SecureRandom random = new SecureRandom();
		random.setSeed(System.currentTimeMillis());
		keygen.initialize(keySize, random);
		return keygen.generateKeyPair();
	}

	
	/**
	 * 使用密钥加密。
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws Exception
	 */
	public static byte[] encrypt(ECKey key,  byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException    {
		Cipher cipher = Cipher.getInstance(ECIES, new BouncyCastleProvider());
		cipher.init(Cipher.ENCRYPT_MODE, (Key)key);
		return cipher.doFinal(input);
	}

	/**
	 * 使用密钥解密。
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws Exception
	 */
	public static byte[] decrypt(ECKey key, byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException  {
		Cipher cipher = Cipher.getInstance(ECIES, new BouncyCastleProvider());
		cipher.init(Cipher.DECRYPT_MODE, (Key)key);
		return cipher.doFinal(input);
	}
}
