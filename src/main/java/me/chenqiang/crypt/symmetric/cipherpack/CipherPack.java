package me.chenqiang.crypt.symmetric.cipherpack;

import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public interface CipherPack {
	public String getTransformation();
	public byte [] getCipherText();
	public void encrypt(SecretKey key, byte [] data) throws GeneralSecurityException ;
	public byte [] decrypt(SecretKey key) throws GeneralSecurityException;
}
