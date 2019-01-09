package me.chenqiang.crypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DhKeyExchange {
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

	public void initialize(int keySize) 
			throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(DH_KEY_ALGORITHM);
		kpg.initialize(keySize);
		KeyPair keyPair = kpg.generateKeyPair();
		this.publicKey = (DHPublicKey) keyPair.getPublic();
		this.privateKey = (DHPrivateKey) keyPair.getPrivate();
	}
	
	public void initialize(DHPublicKey receivedKey) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		DHParameterSpec dhSpec = receivedKey.getParams();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(DH_KEY_ALGORITHM);
		kpg.initialize(dhSpec);
		KeyPair keyPair = kpg.generateKeyPair();
		this.publicKey = (DHPublicKey) keyPair.getPublic();
		this.privateKey = (DHPrivateKey) keyPair.getPrivate();
	}
	
	public void initialize(byte [] x509ReceivedKeyData) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        this.initialize((DHPublicKey)KeyIOUtils.parseX509(x509ReceivedKeyData, DH_KEY_ALGORITHM));
	}
	
	public static SecretKey createLocalSecretKey(DHPrivateKey priKey, DHPublicKey pubKey, String algorithm) 
			throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement ka = KeyAgreement.getInstance(DH_KEY_ALGORITHM);
    	ka.init(priKey);
    	ka.doPhase(pubKey, true);
    	return ka.generateSecret(algorithm);
	}	
}
