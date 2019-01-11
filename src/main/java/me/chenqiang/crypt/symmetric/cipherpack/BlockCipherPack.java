package me.chenqiang.crypt.symmetric.cipherpack;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import me.chenqiang.crypt.symmetric.SymmetricFunctions;

public class BlockCipherPack implements CipherPack{
	public BlockCipherPack(String transformation) {
		this.transformation = transformation;
	}

	protected String transformation;
	protected byte [] cipherText;

	@Override
	public String getTransformation() {
		return this.transformation;
	}
	
	@Override
	public byte[] getCipherText() {
		return this.cipherText;
	}
	
	@Override
	public void encrypt(SecretKey key, byte[] data) 
			throws GeneralSecurityException {
		this.cipherText = SymmetricFunctions.encrypt(key, this.transformation, data);
	}
	
	@Override
	public byte[] decrypt(SecretKey key) 
			throws GeneralSecurityException{
		return SymmetricFunctions.decrypt(key, this.transformation, this.cipherText);
	}
}
