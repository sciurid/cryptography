package me.chenqiang.crypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import me.chenqiang.crypt.asymmetric.DhKeyExchange;

public class DHTest {
	@Before
	public void initialize() {
		Security.addProvider(new BouncyCastleProvider());
	}
	@Test
	public void exchageKey() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchProviderException {
		DhKeyExchange partyA = new DhKeyExchange();
		partyA.initialize(2048);
		
		DHPublicKey pubA = partyA.getPublicKey();
		DhKeyExchange partyB = new DhKeyExchange();
		partyB.initialize(pubA);
		
		for(String algorithm : new String[] {"AES", "DES", "DESede"}) {
			SecretKey secretKeyA = DhKeyExchange.createLocalSecretKey(partyA.getPrivateKey(), partyB.getPublicKey(), algorithm);
			SecretKey secretKeyB = DhKeyExchange.createLocalSecretKey(partyB.getPrivateKey(), partyA.getPublicKey(), algorithm);
			
			String hexA = Hex.encodeHexString(secretKeyA.getEncoded());
			String hexB = Hex.encodeHexString(secretKeyB.getEncoded());
			
			System.out.println(hexA);
			System.out.println(hexB);
			Assert.assertEquals("交换失败", hexA, hexB);
		}
	}
}
