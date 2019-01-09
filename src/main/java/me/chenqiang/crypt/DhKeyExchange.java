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

/**
 * 实现简单DH密钥交换的类
 * @author CHEN Qiang
 *
 */
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

	/**
	 * 生成发起方密钥对
	 * @param keySize 密钥长度
	 * @throws NoSuchAlgorithmException 算法“DH”不存在，实际不应当出现
	 */
	public void initialize(int keySize) 
			throws NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(DH_KEY_ALGORITHM);
		kpg.initialize(keySize);
		KeyPair keyPair = kpg.generateKeyPair();
		this.publicKey = (DHPublicKey) keyPair.getPublic();
		this.privateKey = (DHPrivateKey) keyPair.getPrivate();
	}
	
	/**
	 * 接收方收到发送方的公钥，生成自己的密钥对
	 * @param receivedKey 发送方发来的公钥
	 * @throws NoSuchAlgorithmException 算法“DH”不存在，实际不应当出现
	 * @throws InvalidAlgorithmParameterException 发送方发来的密钥不正确
	 */
	public void initialize(DHPublicKey receivedKey) 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		DHParameterSpec dhSpec = receivedKey.getParams();
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(DH_KEY_ALGORITHM);
		kpg.initialize(dhSpec);
		KeyPair keyPair = kpg.generateKeyPair();
		this.publicKey = (DHPublicKey) keyPair.getPublic();
		this.privateKey = (DHPrivateKey) keyPair.getPrivate();
	}
	
	/**
	 * 接收方收到发送方的公钥数据（X509.1编码），生成自己的密钥对
	 * @param x509ReceivedKeyData 发送方发来的公钥数据（X509.1编码）
	 * @throws NoSuchAlgorithmException 算法“DH”不存在，实际不应当出现
	 * @throws InvalidKeySpecException 发送方发来的密钥数据不正确
	 * @throws InvalidAlgorithmParameterException 发送方发来的密钥不正确
	 */
	public void initialize(byte [] x509ReceivedKeyData) 
			throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
        this.initialize((DHPublicKey)KeyIOUtils.parseX509(x509ReceivedKeyData, DH_KEY_ALGORITHM));
	}
	
	/**
	 * 双方根据交换的密钥计算本地的对称加密密钥，用于实际的加密通信
	 * @param priKey 本方的私钥
	 * @param pubKey 对方的公钥
	 * @param algorithm 实际通信的对称加密算法
	 * @return 实际通信的对称加密密钥
	 * @throws NoSuchAlgorithmException 算法不存在
	 * @throws InvalidKeyException 密钥不正确
	 */
	public static SecretKey createLocalSecretKey(DHPrivateKey priKey, DHPublicKey pubKey, String algorithm) 
			throws NoSuchAlgorithmException, InvalidKeyException {
		KeyAgreement ka = KeyAgreement.getInstance(DH_KEY_ALGORITHM);
    	ka.init(priKey);
    	ka.doPhase(pubKey, true);
    	return ka.generateSecret(algorithm);
	}	
	
	/**
	 * 根据交换的对方公钥计算本地的对称加密密钥，用于实际的加密通信
	 * @param pubKey 对方的公钥
	 * @param algorithm 实际通信的对称加密算法
	 * @return 实际通信的对称加密密钥
	 * @throws InvalidKeyException 算法不存在
	 * @throws NoSuchAlgorithmException 密钥不正确
	 * @see me.chenqiang.crypt.DhKeyExchange#createLocalSecretKey
	 */
	public SecretKey createLocalSecretKey(DHPublicKey pubKey, String algorithm) 
			throws InvalidKeyException, NoSuchAlgorithmException {
		return createLocalSecretKey(this.privateKey, pubKey, algorithm);
	}
}
