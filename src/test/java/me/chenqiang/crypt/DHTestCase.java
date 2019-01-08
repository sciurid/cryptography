package me.chenqiang.crypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import me.chenqiang.crypt.DHKeyExchange;

import org.junit.Assert;

public class DHTestCase {
	@Test
	public void exchageKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
		DHKeyExchange partyA = new DHKeyExchange();
		partyA.initialize(2048);
		
		DHPublicKey pubA = partyA.getPublicKey();
		DHKeyExchange partyB = new DHKeyExchange();
		partyB.initialize(pubA);
		
		for(String algorithm : new String[] {"AES", "DES", "DESede"}) {
			SecretKey secretKeyA = DHKeyExchange.createLocalSecretKey(partyA.getPrivateKey(), partyB.getPublicKey(), algorithm);
			SecretKey secretKeyB = DHKeyExchange.createLocalSecretKey(partyB.getPrivateKey(), partyA.getPublicKey(), algorithm);
			
			String hexA = Hex.encodeHexString(secretKeyA.getEncoded());
			String hexB = Hex.encodeHexString(secretKeyB.getEncoded());
			
			System.out.println(hexA);
			System.out.println(hexB);
			Assert.assertEquals("交换失败", hexA, hexB);
		}
	}
}
