package me.chenqiang.crypt;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.EnumSet;
import java.util.stream.Collectors;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import me.chenqiang.crypt.asymmetric.AsymmetricFunctions;
import me.chenqiang.crypt.asymmetric.CustomECBFunctions;
import me.chenqiang.crypt.asymmetric.RSAFunctions;
import me.chenqiang.crypt.asymmetric.RSAPadding;
import me.chenqiang.crypt.asymmetric.SignAlgorithm;

public class RSATest {
	
	public static final String PLAIN = "噫吁嚱！危乎高哉！蜀道之难，难于上青天。\n"
			+ "蚕丛及鱼凫，开国何茫然！尔来四万八千岁，不与秦塞通人烟。\n"
			+ "西当太白有鸟道，可以横绝峨眉巅。地崩山摧壮士死，然后天梯石栈相钩连。\n"
			+ "上有六龙回日之高标，下有冲波逆折之回川。黄鹤之飞尚不得过，猿猱欲度愁攀援。青泥何盘盘！\n"
			+ "百步九折萦岩峦。扪参历井仰胁息，以手抚膺坐长叹。\n"
			+ "问君西游何时还，畏途巉岩不可攀。但见悲鸟号古木，雄飞雌从绕林间。\n"
			+ "又闻子规啼夜月，愁空山。\n"
			+ "蜀道之难，难于上青天！使人听此凋朱颜。\n"
			+ "连峰去天不盈尺，枯松倒挂倚绝壁。飞湍瀑流争喧豗，砯崖转石万壑雷。\n"
			+ "其险也如此，嗟尔远道之人胡为乎来哉？\n"
			+ "剑阁峥嵘而崔嵬，一夫当关，万夫莫开。所守或匪亲，化为狼与豺。\n"
			+ "朝避猛虎，夕避长蛇。磨牙吮血，杀人如麻。\n"
			+ "锦城虽云乐，不如早还家。\n"
			+ "蜀道之难，难于上青天，侧身西望长咨嗟。\n";
	
	protected RSAPrivateKey privateKey;
	protected RSAPublicKey publicKey;
	
	@Before
	public void initialize() throws NoSuchAlgorithmException {
		Security.addProvider(new BouncyCastleProvider());
		KeyPair kp = RSAFunctions.generateKeyPair(2048);
		this.privateKey = (RSAPrivateKey)kp.getPrivate();
		this.publicKey = (RSAPublicKey)kp.getPublic();
	}
	
	@Test
	public void testEcbPkcs1() 
			throws UnsupportedEncodingException, GeneralSecurityException {
		byte [] source = PLAIN.getBytes("UTF-8");
		byte [] secret = CustomECBFunctions.encrypt(privateKey, RSAPadding.RSA_PKCS1, source);
		byte [] dest = CustomECBFunctions.decrypt(publicKey, RSAPadding.RSA_PKCS1, secret);
		String result = new String(dest, "UTF-8");
		Assert.assertEquals("解密错误", PLAIN, result);
		System.out.println(result);
	}
	
	@Test
	public void listPaddingMargin() 
			throws GeneralSecurityException {
		String [] transformations = (String[]) EnumSet.allOf(RSAPadding.class).stream().map(RSAPadding::getTransformation).collect(Collectors.toList()).toArray(new String[0]);
		int keyBytes = 256;
		for(String trans : transformations) {
			for(int i = keyBytes; i > 0; i--) {
				try {
					AsymmetricFunctions.encrypt(privateKey, trans, new byte[i]);
				}
				catch(Exception e) {
					continue;
				}
				System.out.println(trans + ", " + (256 - i));
				break;
			}
		}
	}
	
	@Test
	public void testEcbOaep() 
			throws UnsupportedEncodingException, GeneralSecurityException {
		
		byte [] source = PLAIN.getBytes("UTF-8");
		byte [] secret = CustomECBFunctions.encrypt(privateKey, RSAPadding.RSA_OAEP_SHA256_MGF1, source);
		byte [] dest = CustomECBFunctions.decrypt(publicKey, RSAPadding.RSA_OAEP_SHA256_MGF1, secret);
		String result = new String(dest, "UTF-8");
		Assert.assertEquals("解密错误", PLAIN, result);
		System.out.println(result);
	}
	
	@Test
	public void testSignature() throws UnsupportedEncodingException, GeneralSecurityException {
		byte [] source = PLAIN.getBytes("UTF-8");
		for(String algorithm : new String[] {
				SignAlgorithm.MD5_RSA, SignAlgorithm.SHA1_RSA, SignAlgorithm.SHA256_RSA,
				SignAlgorithm.SHA384_RSA, SignAlgorithm.SHA512_RSA}) {

			byte [] sig = AsymmetricFunctions.sign(privateKey, source, algorithm);
			boolean result = AsymmetricFunctions.verify(publicKey, source, sig, algorithm);
			Assert.assertTrue("签名错误", result);
		}		
	}
}
