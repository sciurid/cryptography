package me.chenqiang.crypt.asymmetric;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 非对称加密算法进行签名和验证的通用过程。
 * @author CHEN Qiang
 *
 */
public interface AsymmetricFunctions {
	/**
	 * 使用私钥签名。
	 * @param key 密钥
	 * @param data 数据
	 * @param algorithm 算法
	 * @return 签名
	 * @throws GeneralSecurityException
	 */
	public static byte [] sign(PrivateKey key, byte [] data, String algorithm) 
			throws GeneralSecurityException {
		Signature signature = Signature.getInstance(algorithm, new BouncyCastleProvider());
		signature.initSign(key);
		signature.update(data);
		return signature.sign();
	}
	
	/**
	 * 使用公钥验证签名。
	 * @param key 密钥
	 * @param data 数据
	 * @param sig 签名
	 * @param algorithm 算法
	 * @return 签名是否正确
	 * @throws GeneralSecurityException 
	 */
	public static boolean verify(PublicKey key, byte [] data, byte[] sig, String algorithm) 
			throws GeneralSecurityException  {
		Signature signature = Signature.getInstance(algorithm, new BouncyCastleProvider());
		signature.initVerify(key);
		signature.update(data);
		return signature.verify(sig);
	}
	
	/**
	 * 使用密钥（公钥或私钥）加密。
	 * 
	 * 注意长度有限制，与Padding方式有关。由于性能问题一般不用于大量数据加密，而是用于加密和传输对称密钥，然后采用对称加密进行实际的加密传输。
	 * @param key
	 * @param transformation
	 * @param input
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte[] encrypt(Key key, String transformation, byte [] input) 
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(input);
	}
	
	/**
	 * 使用密钥（私钥或公钥）解密，和{@link me.chenqiang.crypt.asymmetric.AsymmetricFunctions#encrypt}采用对偶密钥。
	 * @param key
	 * @param transformation
	 * @param input
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte[] decrypt(Key key, String transformation, byte [] input) 
			throws GeneralSecurityException {
		Cipher cipher = Cipher.getInstance(transformation, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(input);
	}
}
