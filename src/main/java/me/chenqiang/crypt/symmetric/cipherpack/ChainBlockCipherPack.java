package me.chenqiang.crypt.symmetric.cipherpack;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

import me.chenqiang.crypt.symmetric.SymmetricFunctions;

public class ChainBlockCipherPack implements CipherPack{
	protected String transformation;
	protected byte [] iv;
	protected byte [] cipherText;
	
	public ChainBlockCipherPack(String transformation, byte[] iv) {
		this.transformation = transformation;
		this.iv = iv;
	}
	
	public byte[] getIv() {
		return this.iv;
	}
	
	@Override
	public String getTransformation() {
		return this.transformation;
	}
	
	@Override
	public byte[] getCipherText() {
		return this.getCipherText();
	}
	
	@Override
	public void encrypt(SecretKey key, byte[] data) throws GeneralSecurityException {
		this.cipherText = SymmetricFunctions.encrypt(key, this.transformation, this.iv, data);
	}
	
	@Override
	public byte[] decrypt(SecretKey key) throws GeneralSecurityException {
		return SymmetricFunctions.decrypt(key, this.transformation, this.iv, this.cipherText);
	}
	
}
