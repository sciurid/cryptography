package me.chenqiang.crypt.asymmetric;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
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

/**
 * 调用BouncyCastle实现RSA功能类
 *
 * @author CHENQIANG
 *
 *
 * 注意：RSA不适合直接用于加密，而是用于签名和密钥交换。
 * {@link https://crypto.stackexchange.com/questions/2789/is-rsa-in-a-ecb-like-mode-safe-for-bulk-encryption}
 *
 * 对于长度不足的数据块要进行补齐，补齐方法见静态成员的定义。
 * 除了NoPadding和ZeroBytesPadding以外，其他的补齐方法都要占用数据块长度，见{@link me.chenqiang.crypt.asymmetric.RSAFunctions#DIMINUTION}。
 * {@link https://crypto.stackexchange.com/questions/32692/what-is-the-typical-block-size-in-rsa}
 * 
 * 计算公式为 max_block_size = upper(key_size_bits/8) - 2*hash_bytes - 2，例如RSA/None/OAEPWithSHA1AndMGF1Padding，
 * 密钥长度2048bits，sha1的hash_size = 20，则max_block_size = 256-20*2-2=214bytes。
 * 
 * OAEP算法
 * {@link https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding}
 * 
 * MGF1算法
 * {@linkhttps://en.wikipedia.org/wiki/Mask_generation_function}
 * 
 */
public class RSAFunctions implements SignFunctions{
	private RSAFunctions() {}
	
	public static final String RSA = "RSA";
	
	public static final String RSA_PKCS1 = "RSA/None/PKCS1Padding";
	public static final String RSA_NO = "RSA/None/NoPadding";
	public static final String RSA_ZEROBYTES = "RSA/None/ZeroBytesPadding";
	// OAEPPadding的默认值是OAEPWithSHA1AndMGF1Padding
	public static final String RSA_OAEP = "RSA/None/OAEPPadding";
	public static final String RSA_OAEP_MD5_MGF1 = "RSA/None/OAEPWithMD5AndMGF1Padding";
	public static final String RSA_OAEP_SHA1_MGF1 = "RSA/None/OAEPWithSHA1AndMGF1Padding";
	public static final String RSA_OAEP_SHA224_MGF1 = "RSA/None/OAEPWithSHA224AndMGF1Padding";
	public static final String RSA_OAEP_SHA256_MGF1 = "RSA/None/OAEPWithSHA256AndMGF1Padding";
	public static final String RSA_OAEP_SHA384_MGF1 = "RSA/None/OAEPWithSHA384AndMGF1Padding";
	public static final String RSA_OAEP_SHA512_MGF1 = "RSA/None/OAEPWithSHA512AndMGF1Padding";
	public static final String RSA_OAEP_SHA3224_MGF1 = "RSA/None/OAEPWithSHA3-224AndMGF1Padding";
	public static final String RSA_OAEP_SHA3256_MGF1 = "RSA/None/OAEPWithSHA3-256AndMGF1Padding";
	public static final String RSA_OAEP_SHA3384_MGF1 = "RSA/None/OAEPWithSHA3-384AndMGF1Padding";
	public static final String RSA_OAEP_SHA3512_MGF1 = "RSA/None/OAEPWithSHA3-512AndMGF1Padding";
	public static final String RSA_ISO9796 = "RSA/None/ISO9796-1Padding";
	
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
			
	public static byte [] encrypt(Cipher cipher, int keyBitLength, int paddingLength, byte [] source) 
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
	public static byte [] decrypt(Cipher cipher, int keyBitLength, byte [] secret) 
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
	 * @throws NoSuchProviderException 
	 * @throws Exception
	 */
	public static byte[] encrypt(RSAKey key, String transformation, byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, 
			InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException    {
		Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
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
	 * @throws NoSuchProviderException 
	 * @throws Exception
	 */
	public static byte[] decrypt(RSAKey key, String transformation, byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			BadPaddingException, IllegalBlockSizeException, NoSuchProviderException  {
		Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.DECRYPT_MODE, (Key)key);
		return decrypt(cipher, key.getModulus().bitLength(), input);
	}
}
