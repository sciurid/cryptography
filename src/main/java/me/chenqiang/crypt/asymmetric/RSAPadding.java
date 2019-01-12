package me.chenqiang.crypt.asymmetric;

/**
 * RSA加密的各种补齐方法
 * 
 * @author CHEN Qiang
 *
 */
public enum RSAPadding {
	RSA_NO("NoPadding", 0),
	RSA_ZEROBYTE("ZeroBytePadding", 0),
	RSA_PKCS1("PKCS1Padding", 11),
	RSA_OAEP("OAEPPadding", 42),
	RSA_OAEP_MD5_MGF1("OAEPWithMD5AndMGF1Padding", 34),
	RSA_OAEP_SHA1_MGF1("OAEPWithSHA1AndMGF1Padding", 42),
	RSA_OAEP_SHA224_MGF1("OAEPWithSHA224AndMGF1Padding", 58),
	RSA_OAEP_SHA256_MGF1("OAEPWithSHA256AndMGF1Padding", 66),
	RSA_OAEP_SHA384_MGF1("OAEPWithSHA384AndMGF1Padding", 98),
	RSA_OAEP_SHA512_MGF1("OAEPWithSHA512AndMGF1Padding", 130),
	RSA_OAEP_SHA3224_MGF1("OAEPWithSHA3-224AndMGF1Padding", 58),
	RSA_OAEP_SHA3256_MGF1("OAEPWithSHA3-256AndMGF1Padding", 66),
	RSA_OAEP_SHA3384_MGF1("OAEPWithSHA3-384AndMGF1Padding", 98),
	RSA_OAEP_SHA3512_MGF1("OAEPWithSHA3-512AndMGF1Padding", 130),
	RSA_ISO9796("ISO9796-1Padding", 128),
	;
	private String name;
	private int margin;
	private String transformation;
	
	RSAPadding(String name, int margin) {
		this.name = name;
		this.margin = margin;
		this.transformation = String.format("RSA/None/%s", this.name);
	}
	
	@Override
	public String toString() {
		return this.name;
	}
	
	public String getTransformation() {
		return this.transformation;
	}
	
	public int getMargin() {
		return this.margin;
	}
}
