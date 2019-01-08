package me.chenqiang.crypt.rsa;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RSAFunctions {
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
		if(startIndexInclusive < 0) {
			startIndexInclusive = 0;
		}
		if(endIndexExclusive > array.length) {
			endIndexExclusive = array.length;
		}
        final int newSize = endIndexExclusive - startIndexInclusive;
        if(newSize <= 0) {
        	return ERROR_RESULT;
        }
        final byte[] subarray = new byte[newSize];
        System.arraycopy(array, startIndexInclusive, subarray, 0, newSize);
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
	
	/**
	 * 使用RSA私钥签名。
	 * @param key 密钥
	 * @param data 数据
	 * @return 签名
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte [] sign(PrivateKey key, byte [] data, String algorithm) 
			throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		Signature signature = Signature.getInstance(algorithm, new BouncyCastleProvider());
		signature.initSign(key);
		signature.update(data);
		return signature.sign();
	}
	
	/**
	 * 使用RSA公钥验证签名。
	 * @param key 密钥
	 * @param data 数据
	 * @param sig 签名
	 * @return 签名是否正确
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException 
	 */
	public static boolean verify(PublicKey key, byte [] data, byte[] sig, String algorithm) 
			throws SignatureException, InvalidKeyException, NoSuchAlgorithmException  {
		Signature signature = Signature.getInstance(algorithm, new BouncyCastleProvider());
		signature.initVerify(key);
		signature.update(data);
		return signature.verify(sig);
	}
}
