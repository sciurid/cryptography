package me.chenqiang.crypt;

import java.io.IOException;
import java.io.InputStreamReader;
import java.security.KeyPair;

import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.Test;

public class DSATest {
	
	@Test
	public void testDSAFileFormat() throws PKCSException, OperatorCreationException, IOException {
		// 从rsa-private.pem文件中读出RSA密钥对kp
		KeyPair kp = null;
		try(InputStreamReader reader =
				new InputStreamReader(PemTest.class.getResourceAsStream("dsa-private.pem"))) {
			kp = (KeyPair)PemFormatUtils.readPem(reader, null);
		}

		System.out.println(kp.getPrivate().getClass());
		System.out.println(kp.getPublic().getClass());	
	}

}
