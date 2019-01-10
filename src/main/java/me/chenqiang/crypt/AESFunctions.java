package me.chenqiang.crypt;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * AES的各种加密方式操作
 * @author Lancelot
 *
 *
 * {@link https://blog.csdn.net/u011781521/article/details/77932321}
 * {@link https://blog.csdn.net/weixin_42940826/article/details/83687007}
 * {@link https://blog.csdn.net/Vieri_32/article/details/48345023}
 * {@link https://stackoverflow.com/questions/28627398/java-aes-encryption-decryption-procedure-and-usage-of-initialization-vector}
 */

public class AESFunctions {
	public static final String AES = "AES";
	public static final int AES_BLOCK_SIZE = 16;
	
	/**
	 * {@link https://stackoverflow.com/questions/27622625/securerandom-with-nativeprng-vs-sha1prng/27638413}
	 */
	private static SecureRandom KEY_RND;
	static {
		try {
			KEY_RND = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("NO STRONG SECURE RANDOM", e);
		}
	}
	
	/**
	 * 生成AES密钥
	 * 
	 * @param keysize
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public static SecretKey generateSecretKey(int keysize) 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kgen = KeyGenerator.getInstance(AES, BouncyCastleProvider.PROVIDER_NAME);
		kgen.init(keysize, KEY_RND);
		return kgen.generateKey();
	}
	
	/**
	 * {@link https://stackoverflow.com/questions/27622625/securerandom-with-nativeprng-vs-sha1prng/27638413}
	 */
	private static SecureRandom IV_RND = new SecureRandom();
	
	protected static byte [] generateIv(int size) {
		byte [] iv = new byte[AES_BLOCK_SIZE];
		IV_RND.nextBytes(iv);
		return iv;		
	}
	
	public static byte [] generateAesIv() {
		return generateIv(AES_BLOCK_SIZE);
	}
	
	/**
	 * 生成加密器Chipher
	 * 
	 * @param key 密钥
	 * @param transformation 限ECB模式，必须有PKCS5Padding、PKCS7Padding或ISO10126Padding
	 * @param mode 加解密模式
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 */
	protected static Cipher generateCipher(SecretKey key, String transformation, int mode) 
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			InvalidKeyException {
		Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(mode, key);
		return cipher;
	}
	
	/**
	 * 块加密方法，不需要初始向量（IV）。
	 *  
	 * @param key 密钥
	 * @param transformation 模式
	 * @param plaintext 明文
	 * @return 密文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * 
	 * @see me.chenqiang.crypt.AESFunctions#generateCipher
	 */
	public static byte [] encrypt(SecretKey key, String transformation, byte [] plaintext) 
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		return generateCipher(key, transformation, Cipher.ENCRYPT_MODE).doFinal(plaintext);
	}
	
	/**
	 * 块解密方法，不需要初始向量（IV）。
	 * @param key 密钥
	 * @param transformation 模式
	 * @param ciphertext 密文
	 * @return 明文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * 
	 * @see me.chenqiang.crypt.AESFunctions#generateCipher
	 */
	public static byte [] decrypt(SecretKey key, String transformation, byte [] ciphertext) 
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		return generateCipher(key, transformation, Cipher.DECRYPT_MODE).doFinal(ciphertext);
	}
	
	/**
	 * 生成加密器Chipher
	 * 
	 * @param key 密钥
	 * @param transformation CBC/CFB/OFB/CTR模式，可以是NoPadding/PKCS7Padding/ISO10126Padding之一，PKCS5Padding实际和PKCS7Padding一样。
	 * @param iv 初始向量
	 * @param mode 加解密模式
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	protected static Cipher generateCipher(SecretKey key, String transformation, byte [] iv, int mode) 
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(mode, key, new IvParameterSpec(iv));
		return cipher;
	}
	
	
	/**
	 * 块加密方法，需要初始向量（IV）。初始向量应当每次变化，可以（应当）和密文一起传送。
	 * 
	 * @param key 密钥
	 * @param transformation 
	 * @param iv 初始向量
	 * @param plaintext 明文
	 * @return 密文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * 
	 * @see me.chenqiang.crypt.AESFunctions#generateCipher
	 */
	public static byte [] encrypt(SecretKey key, String transformation, byte [] iv, byte [] plaintext) 
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		return generateCipher(key, transformation, iv, Cipher.ENCRYPT_MODE).doFinal(plaintext);
	}
	
	/**
	 * 块解密方法，需要初始向量（IV）。
	 * @param key 密钥
	 * @param transformation 与加密方式相同
	 * @param iv 与解密方式相同
	 * @param ciphertext 密文
	 * @return 明文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static byte [] decrypt(SecretKey key, String transformation, byte [] iv, byte [] ciphertext) 
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, 
			IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		return generateCipher(key, transformation, iv, Cipher.DECRYPT_MODE).doFinal(ciphertext);
	}
	
	/**
	 * 流加密方法，需要初始向量（IV）。初始向量应当每次变化，可以（应当）和密文一起传送。
	 * 
	 * @param key 密钥
	 * @param transformation CBC/CFB/OFB/CTR模式，可以是NoPadding或上述三种padding。
	 * @param iv 初始向量
	 * @param plaintext 明文
	 * @return 密文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static CipherOutputStream createEncryptStream(SecretKey key, String transformation, byte [] iv, OutputStream underlying)
			throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {		
		return new CipherOutputStream(underlying, generateCipher(key, transformation, iv, Cipher.ENCRYPT_MODE));
	}
	
	/**
	 * 流解密方法，需要初始向量（IV）。
	 * @param key 密钥
	 * @param transformation 与加密方式相同
	 * @param iv 与解密方式相同
	 * @param ciphertext 密文
	 * @return 明文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	public static CipherInputStream createDecryptStream(SecretKey key, String transformation, byte [] iv, InputStream underlying)
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		return new CipherInputStream(underlying, generateCipher(key, transformation, iv, Cipher.DECRYPT_MODE));
	}
	
		
	public static final String AES_GCM = "AES/GCM/NoPadding";
	//Recommended by NIST, more or less length will cause extra calculation.
	public static final int DEFAULT_GCM_IV_SIZE = 12;
	//Tag length of 128, 120, 112, 104, 96, 64, 32 is valid. 128 is recommended.
	public static final int DEFAULT_GCM_TAG_SIZE = 128;
	
	public static final byte [] generateGcmIv() throws NoSuchAlgorithmException {
		return generateIv(DEFAULT_GCM_IV_SIZE);
	}
	
	/**
	 * AES-GCM加密的实现
	 * @param key
	 * @param iv
	 * @param associated
	 * @param plaintext
	 * @return
	 * 
	 * {@link https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9}
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	public static byte [] encryptGcm(SecretKey key, byte [] iv, byte [] associated, int tagLength, byte [] plaintext) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, 
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance(AES_GCM, BouncyCastleProvider.PROVIDER_NAME);
		GCMParameterSpec spec = new GCMParameterSpec(tagLength, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		cipher.updateAAD(associated);
		return cipher.doFinal(plaintext);
	}
	
	public static byte [] encryptGcm(SecretKey key, byte [] iv, byte [] associated, byte [] plaintext) 
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, 
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		return encryptGcm(key, iv, associated, DEFAULT_GCM_TAG_SIZE, plaintext);
	}
	
	/**
	 * AES-GCM解密的实现
	 * @param key
	 * @param iv
	 * @param associated
	 * @param tagLength
	 * @param ciphertext
	 * @return
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	public static byte [] decryptGcm(SecretKey key, byte [] iv, byte [] associated, int tagLength, byte [] ciphertext) 
			throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, 
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance(AES_GCM, BouncyCastleProvider.PROVIDER_NAME);
		GCMParameterSpec spec = new GCMParameterSpec(tagLength, iv);
		cipher.init(Cipher.DECRYPT_MODE, key, spec);
		cipher.updateAAD(associated);
		return cipher.doFinal(ciphertext);
	}
	
	public static byte [] decryptGcm(SecretKey key, byte [] iv, byte [] associated, byte [] ciphertext) 
			throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, 
			NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		return decryptGcm(key, iv, associated, DEFAULT_GCM_TAG_SIZE, ciphertext);
	}
}
