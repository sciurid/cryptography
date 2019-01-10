package me.chenqiang.crypt;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAFunctions implements SignFunctions{
	private RSAFunctions() {}
	
	public static final String RSA = "RSA";
	
	public static final String RSA_PKCS1 = "RSA/ECB/PKCS1Padding";
	public static final String RSA_NO = "RSA/ECB/NoPadding";
	// OAEPPadding的默认值是OAEPWithSHA1AndMGF1Padding
	public static final String RSA_OAEP = "RSA/ECB/OAEPPadding";
	public static final String RSA_OAEP_MD5_MGF1 = "RSA/ECB/OAEPWithMD5AndMGF1Padding";
	public static final String RSA_OAEP_SHA1_MGF1 = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
	public static final String RSA_OAEP_SHA224_MGF1 = "RSA/ECB/OAEPWithSHA224AndMGF1Padding";
	public static final String RSA_OAEP_SHA256_MGF1 = "RSA/ECB/OAEPWithSHA256AndMGF1Padding";
	public static final String RSA_OAEP_SHA384_MGF1 = "RSA/ECB/OAEPWithSHA384AndMGF1Padding";
	public static final String RSA_OAEP_SHA512_MGF1 = "RSA/ECB/OAEPWithSHA512AndMGF1Padding";
	public static final String RSA_OAEP_SHA3224_MGF1 = "RSA/ECB/OAEPWithSHA3-224AndMGF1Padding";
	public static final String RSA_OAEP_SHA3256_MGF1 = "RSA/ECB/OAEPWithSHA3-256AndMGF1Padding";
	public static final String RSA_OAEP_SHA3384_MGF1 = "RSA/ECB/OAEPWithSHA3-384AndMGF1Padding";
	public static final String RSA_OAEP_SHA3512_MGF1 = "RSA/ECB/OAEPWithSHA3-512AndMGF1Padding";
	public static final String RSA_ISO9796 = "RSA/ECB/ISO9796-1Padding";
	
	public static final Map<String, Integer> DIMINUTION;
	static {
		Map<String, Integer> map = new HashMap<>();
		map.put(RSAFunctions.RSA_PKCS1, 11);
		map.put(RSAFunctions.RSA_NO, 0);
		map.put(RSAFunctions.RSA_OAEP, 42);
		map.put(RSAFunctions.RSA_OAEP_MD5_MGF1, 34);
		map.put(RSAFunctions.RSA_OAEP_SHA1_MGF1, 42);
		map.put(RSAFunctions.RSA_OAEP_SHA224_MGF1, 58);
		map.put(RSAFunctions.RSA_OAEP_SHA256_MGF1, 66);
		map.put(RSAFunctions.RSA_OAEP_SHA384_MGF1, 98);
		map.put(RSAFunctions.RSA_OAEP_SHA512_MGF1, 130);
		map.put(RSAFunctions.RSA_OAEP_SHA3224_MGF1, 58);
		map.put(RSAFunctions.RSA_OAEP_SHA3256_MGF1, 66);
		map.put(RSAFunctions.RSA_OAEP_SHA3384_MGF1, 98);
		map.put(RSAFunctions.RSA_OAEP_SHA3512_MGF1, 130);
		DIMINUTION = Collections.unmodifiableMap(map);
	}
	
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
	
	public static RSAPrivateKey createPrivateKey(final BigInteger modulus, final BigInteger privateComponent) 
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(modulus, privateComponent);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
	}
	
	public static RSAPublicKey createPublicKey(final BigInteger modulus, final BigInteger publicComponent) 
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, publicComponent);
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		return (RSAPublicKey) keyFactory.generatePublic(keySpec);
	}
	
	public static RSAPublicKey createPublicKey(RSAPrivateCrtKey privateKey) 
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		return createPublicKey(privateKey.getModulus(), privateKey.getPublicExponent());
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
	 * 分段加密方法。注意，由于一般情况下不用RSA进行长加密，建议采用AES/DESede等方法。
	 * @param cipher Cipher对象
	 * @param keyBitLength 密钥长度
	 * @param paddingLength 补全方法对最大明文长度的减少值
	 * @param source 明文数据
	 * @return	密文数据
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException 
	 */
			
	protected static byte [] encrypt(Cipher cipher, int keyBitLength, int paddingLength, byte [] source) 
			throws BadPaddingException, IllegalBlockSizeException {
		//字节数
		int keyByteLength = keyBitLength / 8; 
		int sliceByteLength = keyByteLength - paddingLength; //
		int sliceNum = source.length / sliceByteLength + 1;
		byte[] result = new byte[sliceNum * keyByteLength];
		
		//原文游标
		int i = 0; 
		//密文游标
		int j = 0; 
		
		while(i < source.length) {
			byte[] slice = subarray(source, i, i + sliceByteLength);
			byte[] encrypted = cipher.doFinal(slice);
			System.arraycopy(encrypted, 0, result, j, keyByteLength);
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
	protected static byte [] decrypt(Cipher cipher, int keyBitLength, byte [] secret) 
			throws BadPaddingException, IllegalBlockSizeException {
		int keyByteLength = keyBitLength / 8;
		//密文游标
		int i = 0; 
		//原文游标
		int j = 0; 
		//每块都不超过密文长度，因此最长也不会超过密文长度
		byte[] result = new byte[secret.length]; 
		while(i < secret.length) {
			byte[] plainPart = cipher.doFinal(subarray(secret, i,  i + keyByteLength));
			System.arraycopy(plainPart, 0, result, j, plainPart.length);
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
	 * @throws IllegalBlockSizeException 
	 * @throws Exception
	 */
	public static byte[] encrypt(RSAKey key, String transformation, byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, 
			InvalidKeyException, IllegalBlockSizeException    {
		Cipher cipher = Cipher.getInstance(transformation, new BouncyCastleProvider());
		cipher.init(Cipher.ENCRYPT_MODE, (Key)key);
		return encrypt(cipher, key.getModulus().bitLength(), DIMINUTION.get(transformation), input);
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
	public static byte[] decrypt(RSAKey key, String transformation, byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			BadPaddingException, IllegalBlockSizeException  {
		Cipher cipher = Cipher.getInstance(transformation, new BouncyCastleProvider());
		cipher.init(Cipher.DECRYPT_MODE, (Key)key);
		return decrypt(cipher, key.getModulus().bitLength(), input);
	}
}
