package me.chenqiang.crypt.symmetric;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import javax.crypto.AEADBadTagException;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
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
	
	@Before
	public void init() throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		this.key = AESFunctions.generateAesKey();
	}

	@Test
	public void testECBSupportedPaddings() throws UnsupportedEncodingException, GeneralSecurityException {
		System.out.println("----------------------------ECB PADDING TEST---------------------------------------");
		byte[] longPlain = LONG_STR.getBytes("UTF-8");
		byte[] shortPlain = SHORT_STR.getBytes("UTF-8");
		
		byte [] ciphertext;
		byte [] decrypted;
		for(String padding : SymmetricConsts.getPaddings()) {
			String trans = String.format("%s/%s/%s", AESFunctions.AES, "ECB", padding);
			try {
				ciphertext = SymmetricFunctions.encrypt(key, trans, longPlain);
				decrypted = SymmetricFunctions.decrypt(key, trans, ciphertext);
				Assert.assertArrayEquals(longPlain, decrypted);
				ciphertext = SymmetricFunctions.encrypt(key, trans, shortPlain);
				decrypted = SymmetricFunctions.decrypt(key, trans, ciphertext);
				Assert.assertArrayEquals(shortPlain, decrypted);
				System.out.println(String.format("%-20s : SUPPORTED", trans));
			}
			catch(Exception e) {
				System.out.println(String.format("%-20s : %s", trans, e));
			}
		}
	}
	
	@Test
	public void testStreamSupportedPaddings() throws UnsupportedEncodingException, GeneralSecurityException {
		System.out.println("----------------------------STREAM PADDING TEST---------------------------------------");
		byte[] longPlain = LONG_STR.getBytes("UTF-8");
		byte[] shortPlain = SHORT_STR.getBytes("UTF-8");
		byte [] iv = AESFunctions.generateAesIv();
		byte [] ciphertext;
		byte [] decrypted;
		for(String mode : SymmetricConsts.getStreamModes()) {
			for(String padding : SymmetricConsts.getPaddings()) {
				String trans = String.format("%s/%s/%s", AESFunctions.AES, mode, padding);
				try {
					ciphertext = SymmetricFunctions.encrypt(key, trans, iv, longPlain);
					decrypted = SymmetricFunctions.decrypt(key, trans, iv, ciphertext);
					Assert.assertArrayEquals(longPlain, decrypted);
					ciphertext = SymmetricFunctions.encrypt(key, trans, iv, shortPlain);
					decrypted = SymmetricFunctions.decrypt(key, trans, iv, ciphertext);
					Assert.assertArrayEquals(shortPlain, decrypted);
					System.out.println(String.format("%-20s : SUPPORTED", trans));
				}
				catch(Exception e) {
					System.out.println(String.format("%-20s : %s", trans, e));
				}				
			}
		}
	}
	
	/**
	 * 测试几种padding的兼容程度。
	 * 
	 * @throws GeneralSecurityException
	 * @throws UnsupportedEncodingException
	 * 
	 * 发现PKCS5Padding和PKCS7Padding结果是一样的。
	 */
	@Test
	public void testPadding() 
			throws GeneralSecurityException, UnsupportedEncodingException {
		System.out.println("----------------------------OFB PADDING TEST---------------------------------------");
		byte[] longPlain = LONG_STR.getBytes("UTF-8");
		byte[] iv = AESFunctions.generateAesIv();
		
		List<String> modes = new ArrayList<>();
		modes.addAll(SymmetricConsts.getStreamModes());
		modes.add(SymmetricConsts.OFB8);
		modes.add(SymmetricConsts.OFB16);
		modes.add(SymmetricConsts.OFB24);
		modes.add(SymmetricConsts.OFB128);
		
		for(String mode : modes) {
			System.out.println(mode);
			for(String padding : SymmetricConsts.getPaddings()) {
				try {
					String trans = String.format("AES/%s/%s", mode, padding);
					byte [] ciphertext = SymmetricFunctions.encrypt(this.key, trans, iv, longPlain);
					System.out.println(String.format("%-20s:%s", padding, DigestUtils.md5Hex(ciphertext)));
				}
				catch(Exception e) {
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
	 * 
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	protected boolean testSingleStream(String mode, String padding) 
			throws GeneralSecurityException, IOException {
		byte[] iv = AESFunctions.generateAesIv();
		String trans = String.format("AES/%s/%s", mode, padding);
		
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		CipherOutputStream cos = SymmetricFunctions.createEncryptStream(this.key, trans, iv, bos);
		
		byte[] longPlain = LONG_STR.getBytes("UTF-8");
		cos.write(longPlain);
		cos.flush();
		cos.close();
		
		ByteArrayInputStream bis = new ByteArrayInputStream(bos.toByteArray());
		CipherInputStream cis = SymmetricFunctions.createDecryptStream(this.key, trans, iv, bis);
		
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
		System.out.println("----------------------------STREAM TEST---------------------------------------");
		
		for(String mode : SymmetricConsts.getStreamModes()) {
			System.out.println(mode);
			for(String padding : SymmetricConsts.getPaddings()) {
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
	 * @throws UnsupportedEncodingException
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testGcm() 
			throws GeneralSecurityException, UnsupportedEncodingException {
		System.out.println("----------------------------GCM TEST---------------------------------------");
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
	 * @throws UnsupportedEncodingException
	 * @throws GeneralSecurityException
	 */
	@Test
	public void testErroneousGcm() 
			throws GeneralSecurityException, UnsupportedEncodingException {
		System.out.println("----------------------------ERRORNEOUS GCM TEST---------------------------------------");
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
