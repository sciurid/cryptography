package me.chenqiang.crypt.symmetric;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 对称加密的常用操作
 * 
 * @author CHEN Qiang
 *
 */
public interface SymmetricFunctions {

	/**
	 * 生成密钥
	 * 
	 * @param rnd
	 * @param algorithm
	 * @param keysize
	 * @return
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 */
	public static SecretKey generateSecretKey(SecureRandom rnd, String algorithm, int keysize) 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyGenerator kgen = KeyGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
		kgen.init(keysize, rnd);
		return kgen.generateKey();
	}
			
	/**
	 * 生成随机字节，常用于生成初始向量。
	 * 
	 * @param rnd 
	 * @param size 向量长度
	 * @return
	 */
	public static byte [] generateRandomBytes(Random rnd, int size) {
		byte [] iv = new byte[size];
		rnd.nextBytes(iv);
		return iv;		
	}	
		
	/**
	 * 生成加密器Chipher，不带初始向量。
	 * 
	 * @param key 密钥
	 * @param transformation ECB/None模式，而且应当指明NoPadding以外的其他补全模式。
	 * @param mode 加解密模式
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Cipher generateCipher(SecretKey key, String transformation, int mode) 
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(mode, key);
		return cipher;
	}
	
	/**
	 * 生成加密器Chipher，带初始向量。
	 * 
	 * @param key 密钥
	 * @param transformation CBC/CFB/OFB/CTR模式，可以是NoPadding/PKCS7Padding/ISO10126Padding之一，PKCS5Padding实际和PKCS7Padding一样。
	 * @param iv 初始向量
	 * @param mode 加解密模式
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static Cipher generateCipher(SecretKey key, String transformation, byte [] iv, int mode) 
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(mode, key, new IvParameterSpec(iv));
		return cipher;
	}
	

	
	/**
	 * 块加密方法，不需要初始向量（IV）。
	 *  
	 * @param key 密钥
	 * @param transformation 模式
	 * @param plaintext 明文
	 * @return 密文
	 * @throws GeneralSecurityException
	 * 
	 * @see me.chenqiang.crypt.symmetric.AESFunctions#generateCipher
	 */
	public static byte [] encrypt(SecretKey key, String transformation, byte [] plaintext) 
			throws GeneralSecurityException {
		return SymmetricFunctions.generateCipher(key, transformation, Cipher.ENCRYPT_MODE).doFinal(plaintext);
	}
	
	/**
	 * 块解密方法，不需要初始向量（IV）。
	 * @param key 密钥
	 * @param transformation 模式
	 * @param ciphertext 密文
	 * @return 明文
	 * @throws GeneralSecurityException
	 * 
	 * @see me.chenqiang.crypt.symmetric.AESFunctions#generateCipher
	 */
	public static byte [] decrypt(SecretKey key, String transformation, byte [] ciphertext) 
			throws GeneralSecurityException {
		return SymmetricFunctions.generateCipher(key, transformation, Cipher.DECRYPT_MODE).doFinal(ciphertext);
	}
	
	
	
	
	/**
	 * 块加密方法，需要初始向量（IV）。初始向量应当每次变化，可以（应当）和密文一起传送。
	 * 
	 * @param key 密钥
	 * @param transformation 
	 * @param iv 初始向量
	 * @param plaintext 明文
	 * @return 密文
	 * @throws GeneralSecurityException
	 * 
	 * @see me.chenqiang.crypt.symmetric.AESFunctions#generateCipher
	 */
	public static byte [] encrypt(SecretKey key, String transformation, byte [] iv, byte [] plaintext) 
			throws GeneralSecurityException {
		return SymmetricFunctions.generateCipher(key, transformation, iv, Cipher.ENCRYPT_MODE).doFinal(plaintext);
	}
	
	/**
	 * 块解密方法，需要初始向量（IV）。
	 * @param key 密钥
	 * @param transformation 与加密方式相同
	 * @param iv 与解密方式相同
	 * @param ciphertext 密文
	 * @return 明文
	 * @throws GeneralSecurityException
	 */
	public static byte [] decrypt(SecretKey key, String transformation, byte [] iv, byte [] ciphertext) 
			throws GeneralSecurityException {
		return SymmetricFunctions.generateCipher(key, transformation, iv, Cipher.DECRYPT_MODE).doFinal(ciphertext);
	}
	
	/**
	 * 流加密方法，需要初始向量（IV）。初始向量应当每次变化，可以（应当）和密文一起传送。
	 * 
	 * @param key 密钥
	 * @param transformation CBC/CFB/OFB/CTR模式，可以是NoPadding或上述三种padding。
	 * @param iv 初始向量
	 * @param underlying 用于输出密文的流
	 * @return 密文
	 * @throws GeneralSecurityException
	 */
	public static CipherOutputStream createEncryptStream(SecretKey key, String transformation, byte [] iv, OutputStream underlying)
			throws GeneralSecurityException {		
		return new CipherOutputStream(underlying, SymmetricFunctions.generateCipher(key, transformation, iv, Cipher.ENCRYPT_MODE));
	}
	
	/**
	 * 流解密方法，需要初始向量（IV）。
	 * @param key 密钥
	 * @param transformation 与加密方式相同
	 * @param iv 与解密方式相同
	 * @param underlying 用于输入密文的流
	 * @return 明文
	 * @throws GeneralSecurityException
	 */
	public static CipherInputStream createDecryptStream(SecretKey key, String transformation, byte [] iv, InputStream underlying)
			throws GeneralSecurityException {
		return new CipherInputStream(underlying, SymmetricFunctions.generateCipher(key, transformation, iv, Cipher.DECRYPT_MODE));
	}
}
