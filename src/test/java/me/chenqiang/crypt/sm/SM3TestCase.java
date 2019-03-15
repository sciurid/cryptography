package me.chenqiang.crypt.sm;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class SM3TestCase {
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
	
	@Test
	public void testDigest() {
		SM3Digest digest = new SM3Digest();
		try {
			byte [] plain = PLAIN.getBytes("UTF-8");
			digest.update(plain, 0, plain.length);
			byte [] result = new byte[digest.getDigestSize()];
			int length = digest.doFinal(result, 0);
			System.out.println(length);
			System.out.println(Hex.toHexString(result));
		} catch (UnsupportedEncodingException e) {
		}		
	}
}
