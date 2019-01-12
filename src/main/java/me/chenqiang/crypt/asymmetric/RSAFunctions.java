package me.chenqiang.crypt.asymmetric;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import me.chenqiang.crypt.SecureRandomFunctions;

/**
 * 调用BouncyCastle实现RSA功能类
 *
 * @author CHEN Qiang
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
public class RSAFunctions {
	private RSAFunctions() {}
	
	public static final String RSA = "RSA";
		
	protected static final SecureRandom KEY_RND = SecureRandomFunctions.getStrongRandom();
	
	protected static final int LOW_SECURITY_SIZE = 512;
	protected static final int MEDIUM_SECURITY_SIZE = 1024;
	protected static final int HIGH_SECURITY_SIZE = 2048;
	protected static final int VERY_HIGH_SECURITY_SIZE = 4096;
	
	public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance(RSAFunctions.RSA);
		keygen.initialize(keySize, KEY_RND);
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
}
