package me.chenqiang.crypt.asymmetric;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 非对称加密算法进行签名和验证的通用过程。
 * @author CHEN Qiang
 *
 */
public interface SignFunctions {
	/**
	 * 使用私钥签名。
	 * @param key 密钥
	 * @param data 数据
	 * @param algorithm 算法
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
	 * 使用公钥验证签名。
	 * @param key 密钥
	 * @param data 数据
	 * @param sig 签名
	 * @param algorithm 算法
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
