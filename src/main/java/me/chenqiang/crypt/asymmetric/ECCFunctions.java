package me.chenqiang.crypt.asymmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.ECKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class ECCFunctions implements SignFunctions {
	private ECCFunctions() {}
	
	public static final String EC = "EC";
	public static final String ECIES = "ECIES";
	
	//NIST P256
	public static final String SECP256R1= "secp256r1";	
	//NIST P384
	public static final String SECP384R1= "secp384r1";
	//NIST P521
	public static final String SECP521R1= "secp521r1"; 
	//Curve 25519
	public static final String CURVE25519= "curve25519";
	
	public static final String SHA1_ECDSA = "SHA1withECDSA";
	public static final String NONE_ECDSA = "NONEwithECDSA";
	public static final String SHA224_ECDSA = "SHA224withECDSA";
	public static final String SHA256_ECDSA = "SHA256withECDSA";
	public static final String SHA384_ECDSA = "SHA384withECDSA";
	public static final String SHA512_ECDSA = "SHA512withECDSA";
	
	public static KeyPair generateKeyPair(String curveName) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
		KeyPairGenerator keygen = KeyPairGenerator.getInstance(EC, BouncyCastleProvider.PROVIDER_NAME);
		SecureRandom random = new SecureRandom();
		random.setSeed(System.currentTimeMillis());
		keygen.initialize(ecSpec, random);
		return keygen.generateKeyPair();
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
	public static byte[] encrypt(ECKey key,  byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, 
			InvalidKeyException, IllegalBlockSizeException, NoSuchProviderException    {
		Cipher cipher = Cipher.getInstance(ECIES, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, (Key)key);
		return cipher.doFinal(input);
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
	public static byte[] decrypt(ECKey key, byte [] input) 
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
			BadPaddingException, IllegalBlockSizeException, NoSuchProviderException  {
		Cipher cipher = Cipher.getInstance(ECIES, BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.DECRYPT_MODE, (Key)key);
		return cipher.doFinal(input);
	}
}
