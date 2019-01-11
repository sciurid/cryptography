package me.chenqiang.crypt.symmetric;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import me.chenqiang.crypt.symmetric.DESFunctions;
import me.chenqiang.crypt.symmetric.SymmetricFunctions;

public class DESTest {
	protected final SecureRandom rnd = new SecureRandom();
	
	protected final String PLAIN_TEXT = "莫听穿林打叶声，何妨吟啸且徐行。竹杖芒鞋轻胜马，谁怕？ 一蓑烟雨任平生。\n" + 
			"料峭春风吹酒醒，微冷，山头斜照却相迎。回首向来萧瑟处，归去，也无风雨也无晴。";
	@Before
	public void init() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	@Test
	public void testDES16To24() throws GeneralSecurityException, UnsupportedEncodingException {		
		byte [] k1 = SymmetricFunctions.generateRandomBytes(rnd, 8);
		byte [] k2 = SymmetricFunctions.generateRandomBytes(rnd, 8);
		
		byte [] plain = SymmetricFunctions.generateRandomBytes(rnd, 8);
		byte [] iv = DESFunctions.generateDesIv();
		
		String trans = "DESede/OFB/PKCS5Padding";
		byte [] des3_16 = new byte[DESFunctions.TRIPLE_DES_2_KEY_BITS / 8];
		byte [] des3_24 = new byte[DESFunctions.TRIPLE_DES_3_KEY_BITS / 8];
		System.arraycopy(k1, 0, des3_16, 0, 8);
		System.arraycopy(k2, 0, des3_16, 8, 8);
		System.arraycopy(des3_16, 0, des3_24, 0, 16);
		System.arraycopy(k1, 0, des3_24, 16, 8);
		
		SecretKey key1 = new SecretKeySpec(des3_16, DESFunctions.DESEDE);
		Assert.assertArrayEquals(des3_16, key1.getEncoded());
		SecretKey key2 = new SecretKeySpec(des3_24, DESFunctions.DESEDE);
		Assert.assertArrayEquals(des3_24, key2.getEncoded());
		
		byte [] cipher1 = SymmetricFunctions.encrypt(key1, trans, iv, plain);
		byte [] cipher2 = SymmetricFunctions.encrypt(key2, trans, iv, plain);
		Assert.assertArrayEquals(cipher1, cipher2);
	}
	
	@Test
	public void testAvailableTransformations() 
			throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
		String [] modes = {"EBC", "CBC", "CFB", "OFB", "CTR"};
		String [] paddings = 
			{"NoPadding", "ZeroBytePadding", "PKCS5Padding", "PKCS7Padding", 
					"ISO10126-2Padding", "X923Padding", "ISO7816-4Padding"};
		
		SecretKey key = DESFunctions.generate3DesKey24();
		byte [] plain = PLAIN_TEXT.getBytes("UTF-8");
		byte [] iv = DESFunctions.generateDesIv();
		for(String mode : modes) {
			for(String padding : paddings) {
				String trans = String.format("%s/%s/%s", DESFunctions.DESEDE, mode, padding);
				try {
					byte [] ciphertext = SymmetricFunctions.encrypt(key, trans, iv, plain);
					byte [] decrypted = SymmetricFunctions.decrypt(key, trans, iv, ciphertext);
					Assert.assertArrayEquals(plain, decrypted);
					System.out.println(String.format("%-20s : SUPPORTED", trans));
				}
				catch(Exception e) {
					System.out.println(String.format("%-20s : %s", trans, e));
				}
			}
		}
	}
}

