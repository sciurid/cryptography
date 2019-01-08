package me.chenqiang.crypt;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSAFunctions {
	private RSAFunctions() {}
	private static final Logger LOGGER = LoggerFactory.getLogger(RSAFunctions.class);
	
	public static final int PADDING_DIMINUTION_PKCS1 = 11;
	public static final int PADDING_DIMINUTION_OAEP = 42;
	
	public static final String RSA = "RSA";
	
	public static final String RSA_ECB_PKCS1 = "RSA/ECB/PKCS1Padding";
	public static final String RSA_ECB_OAEP = "RSA/ECB/OAEPPadding";
	public static final String RSA_CBC_PKCS1 = "RSA/CBC/PKCS1Padding";
	public static final String RSA_CBC_OAEP = "RSA/CBC/OAEPPadding";
	
	public static final String MD5_RSA = "MD5withRSA";
	public static final String SHA1_RSA = "SHA1WithRSA";
	public static final String SHA256_RSA = "SHA256withRSA";
	public static final String SHA384_RSA = "SHA384withRSA";
	public static final String SHA512_RSA = "SHA512withRSA";
	
	public static final byte [] ERROR_RESULT = new byte[0];
	public static final String SHALL_NOT_HAPPEN = "不应出现的结果/SHALL NOT HAPPEN";
	
	public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance(RSAFunctions.RSA);
		SecureRandom random = new SecureRandom();
		random.setSeed(System.currentTimeMillis());
		keygen.initialize(keySize, random);
		return keygen.generateKeyPair();
	}
		
	/**
	 * 从字节数据中复制出一段的函数
	 * @param array
	 * @param startIndexInclusive
	 * @param endIndexExclusive
	 * @return
	 */
	protected static byte[] subarray(final byte[] array, int startIndexInclusive, int endIndexExclusive) {
		if(array == null) {
			throw new NullPointerException();
		}
		
		final int start = startIndexInclusive < 0 ? 0 : startIndexInclusive;
		final int end = endIndexExclusive > array.length ? array.length : endIndexExclusive;
        final int newSize = end - start;
        if(newSize <= 0) {
        	return ERROR_RESULT;
        }
        final byte[] subarray = new byte[newSize];
        System.arraycopy(array, start, subarray, 0, newSize);
        return subarray;
    }
	
	/**
	 * 分段加密方法
	 * @param cipher Cipher对象
	 * @param keyBitLength 密钥长度
	 * @param paddingLength 补全方法对最大明文长度的减少值
	 * @param source 明文数据
	 * @return	密文数据
	 * @throws BadPaddingException
	 */
			
	protected static byte [] encrypt(Cipher cipher, int keyBitLength, int paddingLength, byte [] source) throws BadPaddingException {
		int keyByteLength = keyBitLength / 8; //字节数
		int sliceByteLength = keyByteLength - paddingLength; //
		int sliceNum = source.length / sliceByteLength + 1;
		byte[] result = new byte[sliceNum * keyByteLength];
		
		int i = 0; //原文游标
		int j = 0; //密文游标
		
		while(i < source.length) {
			byte[] slice = subarray(source, i, i + sliceByteLength);
			try {
				byte[] encrypted = cipher.doFinal(slice);
				System.arraycopy(encrypted, 0, result, j, keyByteLength);
			} catch (IllegalBlockSizeException e) {
				LOGGER.error(SHALL_NOT_HAPPEN, e);
				return ERROR_RESULT;
			}
			i += sliceByteLength;
			j += keyByteLength;
		}
		return result;
	}
	
	/**
	 * 分段解密核心部分
	 * @param cipher Cipher对象
	 * @param keyBitLength 密钥长度
	 * @param secret 密文数据
	 * @return 原文数据
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	protected static byte [] decrypt(Cipher cipher, int keyBitLength, byte [] secret) throws BadPaddingException {
		int keyByteLength = keyBitLength / 8;
		
		int i = 0; //密文游标
		int j = 0; //原文游标
		
		byte[] result = new byte[secret.length]; //每块都不超过密文长度，因此最长也不会超过密文长度
		while(i < secret.length) {
			byte[] plainPart;
			try {
				plainPart = cipher.doFinal(subarray(secret, i,  i + keyByteLength));
				System.arraycopy(plainPart, 0, result, j, plainPart.length);
			} catch (IllegalBlockSizeException e) {
				LOGGER.error(SHALL_NOT_HAPPEN, e);
				return ERROR_RESULT;
			}
			i += keyByteLength;
			j += plainPart.length;
		}
		
		return subarray(result, 0, j);
	}
	
	/**
	 * 使用密钥加密。
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws Exception
	 */
	public static byte[] encrypt(RSAKey key, String transformation, int paddingDiminution, byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, InvalidKeyException    {
		Cipher cipher = Cipher.getInstance(transformation, new BouncyCastleProvider());
		cipher.init(Cipher.ENCRYPT_MODE, (Key)key);
		return encrypt(cipher, key.getModulus().bitLength(), paddingDiminution, input);
	}

	/**
	 * 使用密钥解密。
	 * @param input
	 * @return
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws BadPaddingException 
	 * @throws Exception
	 */
	public static byte[] decrypt(RSAKey key, String transformation, byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException  {
		Cipher cipher = Cipher.getInstance(transformation, new BouncyCastleProvider());
		cipher.init(Cipher.DECRYPT_MODE, (Key)key);
		return decrypt(cipher, key.getModulus().bitLength(), input);
	}
}
