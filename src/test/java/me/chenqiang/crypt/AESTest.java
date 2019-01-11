package me.chenqiang.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Random;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class AESTest {
	protected SecretKey key;
	
	public static final String LONG_STR = "噫吁嚱！危乎高哉！蜀道之难，难于上青天。"
			+ "蚕丛及鱼凫，开国何茫然！尔来四万八千岁，不与秦塞通人烟。"
			+ "西当太白有鸟道，可以横绝峨眉巅。地崩山摧壮士死，然后天梯石栈相钩连。"
			+ "上有六龙回日之高标，下有冲波逆折之回川。黄鹤之飞尚不得过，猿猱欲度愁攀援。青泥何盘盘！"
			+ "百步九折萦岩峦。扪参历井仰胁息，以手抚膺坐长叹。"
			+ "问君西游何时还，畏途巉岩不可攀。但见悲鸟号古木，雄飞雌从绕林间。"
			+ "又闻子规啼夜月，愁空山。"
			+ "蜀道之难，难于上青天！使人听此凋朱颜。"
			+ "连峰去天不盈尺，枯松倒挂倚绝壁。飞湍瀑流争喧豗，砯崖转石万壑雷。"
			+ "其险也如此，嗟尔远道之人胡为乎来哉？"
			+ "剑阁峥嵘而崔嵬，一夫当关，万夫莫开。所守或匪亲，化为狼与豺。"
			+ "朝避猛虎，夕避长蛇。磨牙吮血，杀人如麻。"
			+ "锦城虽云乐，不如早还家。"
			+ "蜀道之难，难于上青天，侧身西望长咨嗟。";
	
	public static final String SHORT_STR = "啊呀";
	public static final String [] TRANSFORMATIONS = {
			"AES/ECB/NoPadding", "AES/ECB/ZeroBytePadding", "AES/ECB/PKCS5Padding", "AES/ECB/PKCS7Padding", "AES/ECB/ISO10126Padding",
			"AES/CBC/NoPadding", "AES/ECB/ZeroBytePadding", "AES/CBC/PKCS5Padding", "AES/CBC/PKCS7Padding", "AES/CBC/ISO10126Padding",
			"AES/CFB/NoPadding", "AES/ECB/ZeroBytePadding", "AES/CFB/PKCS5Padding", "AES/CFB/PKCS7Padding", "AES/CFB/ISO10126Padding",
			"AES/OFB/NoPadding", "AES/ECB/ZeroBytePadding", "AES/OFB/PKCS5Padding", "AES/OFB/PKCS7Padding", "AES/OFB/ISO10126Padding",
			"AES/CTR/NoPadding", "AES/ECB/ZeroBytePadding", "AES/CTR/PKCS5Padding", "AES/CTR/PKCS7Padding", "AES/CTR/ISO10126Padding"
	};
	
	@Before
	public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		this.key = AESFunctions.generateSecretKey(256);
	}
	
	/**
	 * 测试各种工作模式和补齐的组合，没有初始向量的情况。
	 * 
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * 
	 * EBC和CBC模式都必须要有补齐方式，PKCS7Padding或ISO10126Padding，否则会报错。
	 * 
	 */
	@Test
	public void testBlock1() throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] longPlain = LONG_STR.getBytes("UTF-8");
		byte[] shortPlain = SHORT_STR.getBytes("UTF-8");
		
		for(String trans : TRANSFORMATIONS) {
			byte [] ciphertext = null;
			byte [] decrypted = null;
			
			try {
				ciphertext = AESFunctions.encrypt(this.key, trans, longPlain);
				decrypted = AESFunctions.decrypt(this.key, trans, ciphertext);
				Assert.assertEquals(new String(decrypted, "UTF-8"), LONG_STR);
				System.out.println(String.format("[BLOCK1 LONG]%s -> SUCCESS", trans));
			}
			catch(Exception e) {
				System.out.println(String.format("[BLOCK1 LONG]%s -> %s", trans, e));
			}
			
			try {
				ciphertext = AESFunctions.encrypt(this.key, trans, shortPlain);
				decrypted = AESFunctions.decrypt(this.key, trans, ciphertext);
				Assert.assertEquals(new String(decrypted, "UTF-8"), SHORT_STR);
				System.out.println(String.format("[BLOCK1 SHORT]%s -> SUCCESS", trans));
			}
			catch(Exception e) {
				System.out.println(String.format("[BLOCK1 SHORT]%s -> %s", trans, e));
			}
		}
	}
	

	/**
	 * 测试各种工作模式和补齐的组合，有初始向量的情况。
	 * 
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * 
	 * EBC模式不接受初始向量，否则会报错。
	 * CBC模式都须要有补齐方式，PKCS7Padding或ISO10126Padding，否则会报错。
	 * CBC/CFB/OFB/CTR模式都要有初始向量，否则会报错。
	 * 
	 */
	@Test
	public void testBlock2() throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] longPlain = LONG_STR.getBytes("UTF-8");
		byte[] shortPlain = SHORT_STR.getBytes("UTF-8");
		byte[] iv = AESFunctions.generateAesIv();
		for(String trans : TRANSFORMATIONS) {
			byte [] ciphertext = null;
			byte [] decrypted = null;

			try {
				ciphertext = AESFunctions.encrypt(this.key, trans, iv, shortPlain);
				decrypted = AESFunctions.decrypt(this.key, trans, iv, ciphertext);
				Assert.assertEquals(new String(decrypted, "UTF-8"), SHORT_STR);
				System.out.println(String.format("[BLOCK2 LONG]%s -> SUCCESS", trans));
			}
			catch(Exception e) {
				System.out.println(String.format("[BLOCK2 SHORT]%s -> %s", trans, e));
			}
			try {
				ciphertext = AESFunctions.encrypt(this.key, trans, iv, longPlain);
				decrypted = AESFunctions.decrypt(this.key, trans, iv, ciphertext);
				Assert.assertEquals(new String(decrypted, "UTF-8"), LONG_STR);
				System.out.println(String.format("[BLOCK2 LONG]%s -> SUCCESS", trans));
			}
			catch(Exception e) {
				System.out.println(String.format("[BLOCK2 LONG]%s -> %s", trans, e));
			}
			
		}
	}
	
	/**
	 * 测试几种padding的兼容程度。
	 * 
	 * @throws UnsupportedEncodingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * 
	 * 发现PKCS5Padding和PKCS7Padding结果是一样的。
	 */
	@Test
	public void testPadding() 
			throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, 
			NoSuchProviderException, NoSuchPaddingException,  
			BadPaddingException, InvalidAlgorithmParameterException {
		System.out.println("----------------------------PADDING TEST---------------------------------------");
		byte[] longPlain = LONG_STR.getBytes("UTF-8");
		byte[] iv = AESFunctions.generateAesIv();
		
		String [] modes = {"CBC", "CFB", "OFB", "OFB8", "OFB16", "OFB24","CTR"};
		String [] paddings = {"NoPadding", "PKCS5Padding", "PKCS7Padding", "ISO10126Padding"};
		
		for(String mode : modes) {
			System.out.println(mode);
			for(String padding : paddings) {
				try {
					String trans = String.format("AES/%s/%s", mode, padding);
					byte [] ciphertext = AESFunctions.encrypt(this.key, trans, iv, longPlain);
					System.out.println(String.format("%-20s:%s", padding, DigestUtils.md5Hex(ciphertext)));
				}
				catch(IllegalBlockSizeException e) {
					System.out.println(String.format("%-20s:%s", padding, e));
				}
			}
		}
	}
	
	/**
	 * 流模式加解密测试
	 * 
	 * @param mode 工作模式
	 * @param padding 补齐模式
	 * @return 测试结果
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws IOException
	 */
	protected boolean testSingleStream(String mode, String padding) 
			throws NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, 
			NoSuchProviderException, NoSuchPaddingException, IOException {
		byte[] iv = AESFunctions.generateAesIv();
		String trans = String.format("AES/%s/%s", mode, padding);
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		CipherOutputStream cos = AESFunctions.createEncryptStream(this.key, trans, iv, bos);
		
		byte[] longPlain = LONG_STR.getBytes("UTF-8");
		cos.write(longPlain);
		cos.flush();
		cos.close();
		
		ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
		CipherInputStream cis = AESFunctions.createDecryptStream(this.key, trans, iv, bis);
		
		byte[] decrypted = IOUtils.toByteArray(cis);
		return LONG_STR.equals(new String(decrypted, "UTF-8"));
	}
	
	/**
	 * 测试流模式加解密。
	 * 
	 * CBC模式在NoPadding的时候会出现结尾丢失的情况，出现解密错误。
	 * 
	 */
	@Test
	public void testStream() {
		String [] modes = {"CBC", "CFB", "OFB", "OFB8", "OFB16", "OFB24","CTR"};
		String [] paddings = {"NoPadding", "PKCS5Padding", "PKCS7Padding", "ISO10126Padding"};
		
		for(String mode : modes) {
			System.out.println(mode);
			for(String padding : paddings) {
				try {
					if(this.testSingleStream(mode, padding)) {
						System.out.println(String.format("%-20s:SUCCESS", padding));
					}
					else {
						System.out.println(String.format("%-20s:FAILURE", padding));						
					}
				}
				catch(Exception e) {
					System.out.println(String.format("%-20s:%s", padding, e.getMessage()));
				}
			}
		}
	}
	
	/**
	 * 测试AES-GCM正常加解密的情况
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	@Test
	public void testGcm() 
			throws NoSuchAlgorithmException, UnsupportedEncodingException, 
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
			InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException {
		SecureRandom random = SecureRandom.getInstanceStrong();
		byte [] associated  = "将进酒 唐·李白".getBytes("UTF-8");
		byte [] plaintext = LONG_STR.getBytes("UTF-8");
		
		// 几种iv长度，其中只有12是推荐值
		for(int i : new int []{8, 12, 16, 24, 32}) {
			// 可以允许的tag长度，其中128是推荐值
			for(int t : new int[] {128, 120, 112, 104, 96, 64, 32}) {
				// 随机初始化指定长度的iv
				byte [] iv = new byte[i];
				random.nextBytes(iv);
	
				// 加密
				byte [] ciphertext = AESFunctions.encryptGcm(this.key, iv, associated, t, plaintext);
				// 解密
				byte [] decrypted = AESFunctions.decryptGcm(this.key, iv, associated, t, ciphertext);
				
				// 判断加解密结果
				Assert.assertEquals(LONG_STR, new String(decrypted, "UTF-8"));
			}
		}
	}
	
	
	@Rule
	public ExpectedException expected = ExpectedException.none();
	/**
	 * 测试AES-GCM非正常验证的情况
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 */
	@Test
	public void testErroneousGcm() 
			throws NoSuchAlgorithmException, UnsupportedEncodingException, 
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, 
			InvalidAlgorithmParameterException, NoSuchProviderException, NoSuchPaddingException {
		byte [] associated  = "将进酒 唐·李白".getBytes("UTF-8");
		byte [] plaintext = LONG_STR.getBytes("UTF-8");		
		byte [] iv = AESFunctions.generateGcmIv();
		byte [] ciphertext = AESFunctions.encryptGcm(this.key, iv, associated, plaintext);
		
		expected.expect(AEADBadTagException.class);
		expected.expectMessage("mac check in GCM failed");
		
		ciphertext[new Random().nextInt(ciphertext.length)] ^= (byte)0xFF;
		byte [] decrypted = AESFunctions.decryptGcm(this.key, iv, associated, ciphertext);
		
		Assert.assertEquals(LONG_STR, new String(decrypted, "UTF-8"));		
	}

}
