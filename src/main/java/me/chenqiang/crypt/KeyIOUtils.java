package me.chenqiang.crypt;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 实现X509.1编码数据和PublicKey，PKCS8编码数据和PrivateKey的转换方法。
 * @see java.security.PublicKey#getEncoded
 * @see java.security.PrivateKey#getEncoded
 * @author CHEN Qiang
 *
 */
public interface KeyIOUtils {
	/**
	 * 将X509.1编码数据转为PublicKey对象。
	 * 数据可以来自于 {@link java.security.PublicKey#getEncoded}，也可以来自Openssl，如：
	 * <code>openssl genrsa -out private.pem 2048 && openssl rsa -in private.pem -inform pem -pubout -outform der -out public.der</code>
	 * @param x509
	 * @param algorithm
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static PublicKey parseX509(byte [] x509, String algorithm) 
			throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509);
        return keyFactory.generatePublic(keySpec);
	}
	
	/**
	 * 将PKCS8编码数据转为PrivateKey对象。
	 * 数据可以来自于{@link java.security.PrivateKey#getEncoded}，也可以来自Openssl，如：
	 * <code>openssl genrsa 2048 | openssl pkcs8 -topk8 -inform pem -outform der -nocrypt -out private.der</code>
	 * @param pkcs8
	 * @param algorithm
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static PrivateKey parsePKCS8(byte [] pkcs8, String algorithm) 
			throws GeneralSecurityException {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(pkcs8);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
	}
}
