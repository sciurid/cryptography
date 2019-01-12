package me.chenqiang.crypt.asymmetric;

/**
 * RSA和ECC签名的各种算法。
 * 
 * @author Lancelot
 *
 */
public class SignAlgorithm {
	private SignAlgorithm() {}

	public static final String MD5_RSA = "MD5withRSA";
	public static final String SHA1_RSA = "SHA1WithRSA";
	public static final String SHA256_RSA = "SHA256withRSA";
	public static final String SHA384_RSA = "SHA384withRSA";
	public static final String SHA512_RSA = "SHA512withRSA";	

	public static final String NONE_ECDSA = "NONEwithECDSA";
	public static final String SHA1_ECDSA = "SHA1withECDSA";		
	public static final String SHA224_ECDSA = "SHA224withECDSA";
	public static final String SHA256_ECDSA = "SHA256withECDSA";
	public static final String SHA384_ECDSA = "SHA384withECDSA";
	public static final String SHA512_ECDSA = "SHA512withECDSA";
}
