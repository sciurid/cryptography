package me.chenqiang.crypt.asymmetric;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.interfaces.RSAKey;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 简单的ECB加密解密方式，主要用于演示RSA块加密解密的大小问题。
 * 不宜用于实际使用。
 * @author CHEN Qiang
 *
 */
public class CustomECBFunctions {
	private CustomECBFunctions() {}
	
	/**
	 * 简单实现的ECB模式加密。
	 * @param cipher
	 * @param plainText
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte[] encrypt(Cipher cipher, byte [] plainText) throws GeneralSecurityException {
		int blockSize = cipher.getBlockSize();
		int outputSize = cipher.getOutputSize(blockSize);
		byte[] blockPlain = new byte[blockSize];
		
		ByteBuffer src = ByteBuffer.wrap(plainText);
		ByteBuffer dst = ByteBuffer.allocate(((plainText.length - 1) / blockSize + 1) * outputSize);
		while(src.hasRemaining()) {
			if(src.remaining() < blockSize) {
				blockPlain = new byte[src.remaining()];
			}
			
			src.get(blockPlain);
			dst.put(cipher.doFinal(blockPlain));
		}
		
		dst.flip();
		return dst.array();
	}
	
	/**
	 * 简单实现的ECB模式解密。
	 * @param cipher
	 * @param plainText
	 * @return
	 * @throws GeneralSecurityException
	 */
	public static byte[] decrypt(Cipher cipher, byte[] cipherText) throws GeneralSecurityException {
		ByteBuffer src = ByteBuffer.wrap(cipherText);
		ByteBuffer dst = ByteBuffer.allocate(cipherText.length);
		
		byte[] blockCipher = new byte[cipher.getBlockSize()];
		while(src.hasRemaining()) {
			src.get(blockCipher);
			dst.put(cipher.doFinal(blockCipher));
		}
		dst.flip();
		byte[] plainText = new byte[dst.remaining()];
		dst.get(plainText);
		return plainText;
	}
	
	
	/**
	 * 使用密钥加密。
	 * @param input
	 * @return
	 * @throws GeneralSecurityException 
	 */
	public static byte[] encrypt(RSAKey key, RSAPadding padding, byte [] input) 
			throws GeneralSecurityException    {
		Cipher cipher = Cipher.getInstance(padding.getTransformation(), BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, (Key)key);
		return encrypt(cipher, input);
	}

	/**
	 * 使用密钥解密。
	 * @param input
	 * @return
	 */
	public static byte[] decrypt(RSAKey key, RSAPadding padding, byte [] input) 
			throws GeneralSecurityException  {
		Cipher cipher = Cipher.getInstance(padding.getTransformation(), BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.DECRYPT_MODE, (Key)key);
		return decrypt(cipher, input);
	}
}
