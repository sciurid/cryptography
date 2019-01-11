package me.chenqiang.crypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class RSATest {
	
	public static final String PLAIN = "噫吁嚱！危乎高哉！蜀道之难，难于上青天。"
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
			throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
		byte [] source = PLAIN.getBytes("UTF-8");
		byte [] secret = RSAFunctions.encrypt(privateKey, RSAFunctions.RSA_PKCS1, source);
		byte [] dest = RSAFunctions.decrypt(publicKey, RSAFunctions.RSA_PKCS1, secret);
		String result = new String(dest, "UTF-8");
		Assert.assertEquals("解密错误", PLAIN, result);
		System.out.println(result);
	}
	
	@Test
	public void listPaddingDiminution() 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		String [] transformations = {
				RSAFunctions.RSA_PKCS1,
				RSAFunctions.RSA_NO,
				RSAFunctions.RSA_ZEROBYTES,
				RSAFunctions.RSA_OAEP,
				RSAFunctions.RSA_OAEP_MD5_MGF1,
				RSAFunctions.RSA_OAEP_SHA1_MGF1,
				RSAFunctions.RSA_OAEP_SHA224_MGF1,
				RSAFunctions.RSA_OAEP_SHA256_MGF1,
				RSAFunctions.RSA_OAEP_SHA384_MGF1,
				RSAFunctions.RSA_OAEP_SHA512_MGF1,
				RSAFunctions.RSA_OAEP_SHA3224_MGF1,
				RSAFunctions.RSA_OAEP_SHA3256_MGF1,
				RSAFunctions.RSA_OAEP_SHA3384_MGF1,
				RSAFunctions.RSA_OAEP_SHA3512_MGF1
		};
		for(String trans : transformations) {
			for(int i = 256; i > 0; i--) {
				try {
					Cipher cipher = Cipher.getInstance(trans, BouncyCastleProvider.PROVIDER_NAME);
					cipher.init(Cipher.ENCRYPT_MODE, privateKey);
					RSAFunctions.encrypt(cipher, privateKey.getModulus().bitLength(), 0, new byte[i]);
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
			throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, 
			BadPaddingException, IllegalBlockSizeException, NoSuchProviderException {
		
		byte [] source = PLAIN.getBytes("UTF-8");
		byte [] secret = RSAFunctions.encrypt(privateKey, RSAFunctions.RSA_OAEP_SHA256_MGF1, source);
		byte [] dest = RSAFunctions.decrypt(publicKey, RSAFunctions.RSA_OAEP_SHA256_MGF1, secret);
		String result = new String(dest, "UTF-8");
		Assert.assertEquals("解密错误", PLAIN, result);
		System.out.println(result);
	}
	
	@Test
	public void testSignature() throws UnsupportedEncodingException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		byte [] source = PLAIN.getBytes("UTF-8");
		for(String algorithm : new String[] {
				RSAFunctions.MD5_RSA, RSAFunctions.SHA1_RSA, RSAFunctions.SHA256_RSA,
				RSAFunctions.SHA384_RSA, RSAFunctions.SHA512_RSA}) {

			byte [] sig = SignFunctions.sign(privateKey, source, algorithm);
			boolean result = SignFunctions.verify(publicKey, source, sig, algorithm);
			Assert.assertTrue("签名错误", result);
		}		
	}
}
