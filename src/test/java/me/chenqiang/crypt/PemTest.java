package me.chenqiang.crypt;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.Assert;
import org.junit.Test;

import me.chenqiang.crypt.asymmetric.RSAFunctions;


/**
 * PEM文件读写的单元测试
 * @author Lancelot
 *
 */
public class PemTest {
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
			throws OperatorCreationException, IOException, PKCSException, NoSuchAlgorithmException, InvalidKeySpecException {
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
			byte [] raw = new byte[1024 * 5];
			int count = IOUtils.read(is, raw);
			Assert.assertTrue("DER文件长度过长", count < raw.length);
			data = new byte[count];
			System.arraycopy(raw, 0, data, 0, count);
			
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
			byte [] raw = new byte[1024 * 5];
			int count = IOUtils.read(is, raw);
			Assert.assertTrue("DER文件长度过长", count < raw.length);
			data = new byte[count];
			System.arraycopy(raw, 0, data, 0, count);
			
			Assert.assertArrayEquals(pubOrigin.getEncoded(), data);
		}
		
		//从DER格式的公钥文件中读出公钥，和pubOrigin对比
		RSAPublicKey pubDer = (RSAPublicKey) KeyIOUtils.parseX509(data, RSAFunctions.RSA);
		Assert.assertEquals(pubOrigin, pubDer);
	}
}
