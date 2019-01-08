package me.chenqiang.crypt.rsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DHKeyExchange {
	public static final String DH_KEY_ALGORITHM = "DH";
	
	public static final String AES = "AES";
	public static final String DES = "DES";
	public static final String DES_EDE ="DESede";
	
	protected DHPublicKey publicKey;
	protected DHPrivateKey privateKey;
	
	public DHPublicKey getPublicKey() {
		return this.publicKey;
	}
	
	public DHPrivateKey getPrivateKey() {
		return this.privateKey;
	}
	
	public static DHPublicKey parseX509(byte [] x509) 
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509);
        KeyFactory keyFactory = KeyFactory.getInstance(DH_KEY_ALGORITHM);
        return (DHPublicKey)keyFactory.generatePublic(keySpec);
	}
	
	public static DHPrivateKey parsePKCS1(byte [] pkcs1) 
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(pkcs1);
        KeyFactory keyFactory = KeyFactory.getInstance(DH_KEY_ALGORITHM);
        return (DHPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
	}
	
	public void initialize(int keySize) 
			throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(DH_KEY_ALGORITHM);
		kpg.initialize(keySize);
		KeyPair keyPair = kpg.generateKeyPair();
		this.publicKey = (DHPublicKey) keyPair.getPublic();
		this.privateKey = (DHPrivateKey) keyPair.getPrivate();
	}
	
	public void initialize(DHPublicKey receivedkey) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		DHParameterSpec dhSpec = receivedkey.getParams();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(DH_KEY_ALGORITHM);
		kpg.initialize(dhSpec);
		KeyPair keyPair = kpg.generateKeyPair();
		this.publicKey = (DHPublicKey) keyPair.getPublic();
		this.privateKey = (DHPrivateKey) keyPair.getPrivate();
	}
	
	public void initialize(byte [] x509ReceivedKeyData) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        this.initialize(parseX509(x509ReceivedKeyData));
	}
	
	public static SecretKey createLocalSecretKey(DHPrivateKey priKey, DHPublicKey pubKey, String algorithm) 
			throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement ka = KeyAgreement.getInstance(DH_KEY_ALGORITHM);
    	ka.init(priKey);
    	ka.doPhase(pubKey, true);
    	return ka.generateSecret(algorithm);
	}	
}
