package me.chenqiang.crypt.asymmetric;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;

import javax.crypto.Cipher;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

import me.chenqiang.crypt.SecureRandomFunctions;

/**
 * 椭圆曲线加密的操作类。
 * 
 * @author CHEN Qiang
 *
 */
public class ECCFunctions {
	private ECCFunctions() {}
	
	public static final class Curve {
		private Curve() {}
		//NIST P256
		public static final String SECP256R1= "secp256r1";	
		//NIST P384
		public static final String SECP384R1= "secp384r1";
		//NIST P521
		public static final String SECP521R1= "secp521r1"; 
		//Curve 25519
		public static final String CURVE25519= "curve25519";
	}
	
	public static final String EC = "EC";
	public static final String ECIES = "ECIES";
	
	protected static final SecureRandom KEY_RND = SecureRandomFunctions.getStrongRandom();
	
	public static KeyPair generateKeyPair(String curveName) 
			throws GeneralSecurityException {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
		KeyPairGenerator keygen = KeyPairGenerator.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME);
		keygen.initialize(ecSpec, KEY_RND);
		return keygen.generateKeyPair();
	}

	
	/**
	 * 使用密钥加密。
	 * @param input
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte[] encrypt(ECKey key,  byte [] input) 
			throws GeneralSecurityException    {
		Cipher cipher = Cipher.getInstance(ECIES, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, (Key)key);
		return cipher.doFinal(input);
	}

	/**
	 * 使用密钥解密。
	 * @param input
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte[] decrypt(ECKey key, byte [] input) 
			throws GeneralSecurityException  {
		Cipher cipher = Cipher.getInstance(ECIES, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.DECRYPT_MODE, (Key)key);
		return cipher.doFinal(input);
	}
}
