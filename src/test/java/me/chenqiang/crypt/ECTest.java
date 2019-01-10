package me.chenqiang.crypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class ECTest {
	
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
	
	protected ECPrivateKey privateKey;
	protected ECPublicKey publicKey;
	
	@Before
	public void initialize() 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		KeyPair kp = ECCFunctions.generateKeyPair(ECCFunctions.CURVE25519);
		this.privateKey = (ECPrivateKey)kp.getPrivate();
		this.publicKey = (ECPublicKey)kp.getPublic();
	}
	
	@Test
	public void testEncrytion() 
			throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
		byte [] source = PLAIN.getBytes("UTF-8");
		byte [] secret = ECCFunctions.encrypt(this.publicKey, source);
		byte [] dest = ECCFunctions.decrypt(this.privateKey, secret);
		String result = new String(dest, "UTF-8");
		Assert.assertEquals("解密错误", PLAIN, result);
		System.out.println(result);
	}
	
	@Test
	public void testSignature() throws UnsupportedEncodingException, InvalidKeyException, SignatureException, NoSuchAlgorithmException {
		byte [] source = PLAIN.getBytes("UTF-8");
		for(String algorithm : new String[] {"NONEwithECDSA", "SHA1withECDSA", "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"}) {
			byte [] sig = SignFunctions.sign(privateKey, source, algorithm);
			boolean result = SignFunctions.verify(publicKey, source, sig, algorithm);
			Assert.assertTrue("签名错误", result);
		}		
	}
}
