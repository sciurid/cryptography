package me.chenqiang.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import me.chenqiang.crypt.asymmetric.RSAFunctions;


/**
 * PEM文件读写的单元测试
 * @author CHEN Qiang
 *
 */
public class PemTest {
	@Before
	public void initialize() 
			throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
	}
	/*
	 * 以rsa-private.pem为最原始文件进行各种不同格式文件的读取验证
	 * 1. 生成原始密钥文件
	 * openssl genrsa -out rsa-private.pem 2048
	 * OpenSSL默认生成的是PKCS1编码的私钥（密钥对），格式如下：
	 * -----BEGIN RSA PRIVATE KEY-----
	 * ENCODED DATA
	 * -----END RSA PRIVATE KEY-----
	 * 
	 * 2. 将私钥文件转为PKCS8编码
	 * Java默认使用的是PKCS8编码的私钥，所以使用OpenSSL转换成PKCS8编码的PEM格式和DER格式分别检验
	 * openssl pkcs8 -topk8 -in rsa-private.pem -outform pem -out rsa-private-pkcs8.pem -nocrypt
	 * openssl pkcs8 -topk8 -in rsa-private.pem -outform der -out rsa-private-pkcs8.der -nocrypt
	 * 
	 * 3. 从私钥文件中生成PEM和DER格式的私钥
	 * openssl rsa -inform pem -in rsa-private.pem -pubout -outform pem -out rsa-public.pem
	 * openssl rsa -inform pem -in rsa-private.pem -pubout -outform der -out rsa-public.der
	 * 
	 */
	
	@Test
	public void testRSAFileFormat() 
			throws OperatorCreationException, IOException, PKCSException, GeneralSecurityException {
		// 从rsa-private.pem文件中读出RSA密钥对kp
		KeyPair kp = null;
		try(InputStreamReader reader =
				new InputStreamReader(PemTest.class.getResourceAsStream("rsa-private.pem"))) {
			kp = (KeyPair)PemFormatUtils.readPem(reader, null);
		}

		// 比较PKCS1和PKCS8的PEM编码文件中获得的私钥
		RSAPrivateKey privOrigin = (RSAPrivateKey) kp.getPrivate();
		try(InputStreamReader reader =
				new InputStreamReader(PemTest.class.getResourceAsStream("rsa-private-pkcs8.pem"))) {
			RSAPrivateCrtKey privPkcs8Pem = (RSAPrivateCrtKey)PemFormatUtils.readPem(reader, null);
			Assert.assertEquals(privOrigin, privPkcs8Pem);
		}
				
		// 从rsa-private-pkcs8.der文件中读出私钥数据，和privOrigin.getEncoded()的数据应当是相等的
		byte [] data = null;
		try(InputStream is = PemTest.class.getResourceAsStream("rsa-private-pkcs8.der")) {
			data = IOUtils.toByteArray(is);			
			Assert.assertArrayEquals(privOrigin.getEncoded(), data);
		}
		
		// 从rsa-private-pkcs8.der文件中读出私钥数据生成私钥，和privOrigin相等的
		RSAPrivateKey privDerPkcs8 =  (RSAPrivateKey) KeyIOUtils.parsePKCS8(data, RSAFunctions.RSA);	
		Assert.assertEquals(privOrigin, privDerPkcs8);
		
		//比较PEM格式的公钥
		RSAPublicKey pubOrigin = (RSAPublicKey) kp.getPublic();
		try(InputStreamReader reader = 
				new InputStreamReader(PemTest.class.getResourceAsStream("rsa-public.pem"))) {
			RSAPublicKey pubPem = (RSAPublicKey) PemFormatUtils.readPem(reader, null);
			Assert.assertEquals(pubOrigin, pubPem);
		}
		
		//比较DER格式的公钥
		try(InputStream is = PemTest.class.getResourceAsStream("rsa-public.der")) {
			data = IOUtils.toByteArray(is);
			Assert.assertArrayEquals(pubOrigin.getEncoded(), data);
		}
		
		//从DER格式的公钥文件中读出公钥，和pubOrigin对比
		RSAPublicKey pubDer = (RSAPublicKey) KeyIOUtils.parseX509(data, RSAFunctions.RSA);
		Assert.assertEquals(pubOrigin, pubDer);
	}
	
	/**
	 * 
	 * openssl dsaparam -genkey 2048 -outform pem -out dsa-param.pem
	 * openssl gendsa -out dsa-private.pem dsa-param.pem
	 * openssl dsa -inform pem -in dsa-private.pem -outform der -out dsa-private.der
	 * openssl dsa -inform pem -in dsa-private.pem -pubout -outform der -out dsa-public.der
	 * openssl dsa -inform pem -in dsa-private.pem -pubout -outform pem -out dsa-public.pem
	 * openssl pkcs8 -topk8 -inform pem -in dsa-private.pem -outform der -out dsa-private-pkcs8.der -nocrypt
	 * 
	 * @throws PKCSException
	 * @throws OperatorCreationException
	 * @throws IOException
	 * @throws GeneralSecurityException 
	 */
	@Test
	public void testDSAFileFormat() 
			throws PKCSException, OperatorCreationException, IOException, GeneralSecurityException {
		// 从dsa-private.pem文件中读出RSA密钥对kp
		KeyPair kp = null;
		try(InputStreamReader reader =
				new InputStreamReader(PemTest.class.getResourceAsStream("dsa-private.pem"))) {
			kp = (KeyPair)PemFormatUtils.readPem(reader, null);
		}
		DSAPrivateKey originPrivate = (DSAPrivateKey) kp.getPrivate();
		DSAPublicKey originPublic = (DSAPublicKey) kp.getPublic();
		
		try(InputStreamReader reader =
				new InputStreamReader(PemTest.class.getResourceAsStream("dsa-public.pem"))) {
			DSAPublicKey pemPublic = (DSAPublicKey) PemFormatUtils.readPem(reader, null);
			Assert.assertArrayEquals(originPublic.getEncoded(), pemPublic.getEncoded());
		}		
		
		try (InputStream is = PemTest.class.getResourceAsStream("dsa-public.der")){
			byte [] data = IOUtils.toByteArray(is);
			DSAPublicKey derPublic = (DSAPublicKey) KeyIOUtils.parseX509(data, "DSA");
			Assert.assertArrayEquals(data, derPublic.getEncoded());
			Assert.assertArrayEquals(originPublic.getEncoded(), derPublic.getEncoded());
		}
		
		try (InputStream is = PemTest.class.getResourceAsStream("dsa-private-pkcs8.der")){
			byte [] data = IOUtils.toByteArray(is);
			DSAPrivateKey derPrivate = (DSAPrivateKey) KeyIOUtils.parsePKCS8(data, "DSA");
			Assert.assertArrayEquals(data, derPrivate.getEncoded());
			Assert.assertArrayEquals(originPrivate.getEncoded(), derPrivate.getEncoded());
		}		
		
		
		 
	}
}
