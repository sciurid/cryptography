package me.chenqiang.crypt.symmetric;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import me.chenqiang.crypt.SecureRandomFunctions;

/**
 * 调用BouncyCastle实现AES加解密的类
 * 
 * @author CHEN Qiang
 *
 * **AES特点**
 * 块大小（block size）：128bit
 * 密钥长度（key size）：128/192/256bit，推荐256bit
 * 工作模式（mode）：块模式（ECB/CBC）、流模式（CFB/OFB/CTR）
 * 补齐方式（padding scheme）：NoPadding/ZeroBytesPadding/PKCS5Padding/PKCS7Padding/ISO10126Padding
 * 初始向量（initialization vector)：长度和密钥长度一致
 * 
 * 加密后，发送方传递算法transformation（工作模式、补齐方式）、初始向量iv和密文给接收方。
 * 
 * **AES-GCM特点**
 * 属于流模式（GCM）
 * 标签长度（tag length）：128（推荐）, 120, 112, 104, 96, 64, 32
 * 初始向量（initialization vector)：推荐12 
 * 
 * 加密后，发送方传递算法transformation（工作模式、补齐方式）、初始向量iv、附加信息associated data和密文给接收方。
 *
 * {@link https://blog.csdn.net/u011781521/article/details/77932321}
 * {@link https://blog.csdn.net/weixin_42940826/article/details/83687007}
 * {@link https://blog.csdn.net/Vieri_32/article/details/48345023}
 * {@link https://stackoverflow.com/questions/28627398/java-aes-encryption-decryption-procedure-and-usage-of-initialization-vector}
 */

public class AESFunctions implements SymmetricFunctions{
	private AESFunctions() {
		
	}
	public static final String AES = SymmetricConsts.AES;
	public static final int AES_BLOCK_SIZE = 16;
	public static final int RECOMMENDED_AES_KEY_SIZE = 256;
	
	/**
	 * 用于生成密钥的随机数发生器，以类静态成员方式共享。
	 * 
	 * 关于可能的性能问题：
	 * 
	 * {@link https://stackoverflow.com/questions/27622625/securerandom-with-nativeprng-vs-sha1prng/27638413}
	 * {@link https://stackoverflow.com/questions/1461568/is-securerandom-thread-safe}
	 * 
	 * If many threads are using a single SecureRandom, there might be contention that hurts performance. 
	 * On the other hand, initializing a SecureRandom instance can be relatively slow. 
	 * Whether it is best to share a global RNG, or to create a new one for each thread will depend on your application. 
	 * The ThreadLocalRandom class could be used as a pattern to provide a solution that supports SecureRandom.
	 * 
	 * 
	 */
	private static final SecureRandom KEY_RND = SecureRandomFunctions.getStrongRandom();
	private static final SecureRandom IV_RND  = new SecureRandom();
	
	public static SecretKey generateAesKey(int keysize) 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return SymmetricFunctions.generateSecretKey(KEY_RND, AES, keysize);
	}
	
	public static SecretKey generateAesKey() 
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return generateAesKey(RECOMMENDED_AES_KEY_SIZE);
	}
	
	/**
	 * {@link https://stackoverflow.com/questions/27622625/securerandom-with-nativeprng-vs-sha1prng/27638413}
	 */
	
	protected static byte [] generateIv(int size) {
		return SecureRandomFunctions.generateRandomBytes(IV_RND, size);		
	}
	
	public static byte [] generateAesIv() {
		return generateIv(AES_BLOCK_SIZE);
	}	
		
	public static final String AES_GCM = "AES/GCM/NoPadding";
	//Recommended by NIST, more or less length will cause extra calculation.
	public static final int RECOMMENDED_GCM_IV_SIZE = 12;
	//Tag length of 128, 120, 112, 104, 96, 64, 32 is valid. 128 is recommended.
	public static final int RECOMMENDED_GCM_TAG_SIZE = 128;
	
	public static final byte [] generateGcmIv() {
		return generateIv(RECOMMENDED_GCM_IV_SIZE);
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
	 * @throws GeneralSecurityException 
	 */
	public static byte [] encryptGcm(SecretKey key, byte [] iv, byte [] associated, int tagLength, byte [] plaintext) 
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(AES_GCM, BouncyCastleProvider.PROVIDER_NAME);
		GCMParameterSpec spec = new GCMParameterSpec(tagLength, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);
		cipher.updateAAD(associated);
		return cipher.doFinal(plaintext);
	}
	
	/**
	 * AES-GCM加密的实现，采用默认的tag长度（128bits）。
	 * @param key
	 * @param iv
	 * @param associated
	 * @param plaintext
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte [] encryptGcm(SecretKey key, byte [] iv, byte [] associated, byte [] plaintext) 
			throws GeneralSecurityException {
		return encryptGcm(key, iv, associated, RECOMMENDED_GCM_TAG_SIZE, plaintext);
	}
	
	/**
	 * AES-GCM解密的实现
	 * @param key
	 * @param iv
	 * @param associated
	 * @param tagLength
	 * @param ciphertext
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte [] decryptGcm(SecretKey key, byte [] iv, byte [] associated, int tagLength, byte [] ciphertext) 
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(AES_GCM, BouncyCastleProvider.PROVIDER_NAME);
		GCMParameterSpec spec = new GCMParameterSpec(tagLength, iv);
		cipher.init(Cipher.DECRYPT_MODE, key, spec);
		cipher.updateAAD(associated);
		return cipher.doFinal(ciphertext);
	}
	
	/**
	 * AES-GCM解密的实现，采用默认的tag长度（128bits）。
	 * @param key
	 * @param iv
	 * @param associated
	 * @param ciphertext
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte [] decryptGcm(SecretKey key, byte [] iv, byte [] associated, byte [] ciphertext) 
			throws GeneralSecurityException {
		return decryptGcm(key, iv, associated, RECOMMENDED_GCM_TAG_SIZE, ciphertext);
	}
}
