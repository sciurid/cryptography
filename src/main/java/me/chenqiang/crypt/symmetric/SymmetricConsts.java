package me.chenqiang.crypt.symmetric;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 对称加密的各种工作模式和补全模式
 * 
 * 注意，BouncyCastle中的补全模式名称中居然有笔误。
 * @author CHEN Qiang
 *
 */
public final class SymmetricConsts {
	private SymmetricConsts() {}
	
	public static final String AES = "AES";
	public static final String DES = "DES";
	public static final String DESEDE = "DESede";
	
	public static final String EBC = "EBC";
	public static final String CBC = "CBC";
	public static final String CFB = "CFB";
	public static final String OFB = "OFB";
	public static final String OFB1 = "OFB1";
	public static final String OFB8 = "OFB8";
	public static final String OFB16 = "OFB16";
	public static final String OFB24 = "OFB24";
	public static final String OFB128 = "OFB128";
	public static final String CTR = "CTR";
		
	public static final List<String> getStreamModes() {
		return Collections.unmodifiableList(Arrays.asList(CBC, CFB, OFB, CTR));
	}
	
	public static final String  NO_PADDING = "NoPadding";
	public static final String  ZERO_BYTE_PADDING = "ZeroBytePadding";
	public static final String  PKCS5_PADDING = "PKCS5Padding";
	public static final String  PKCS7_PADDING = "PKCS7Padding";
	public static final String  ISO10126_2_PADDING = "ISO10126-2Padding";
	public static final String  X923_PADDING = "X923Padding";
	public static final String  ISO7816_4_PADDING = "ISO7816-4Padding";
	
	public static final List<String> getPaddings() {

		return Collections.unmodifiableList(Arrays.asList(
				NO_PADDING, ZERO_BYTE_PADDING, PKCS5_PADDING, PKCS7_PADDING,
				ISO10126_2_PADDING, X923_PADDING, ISO7816_4_PADDING
				));
	}

}