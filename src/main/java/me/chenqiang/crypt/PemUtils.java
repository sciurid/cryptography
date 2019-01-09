package me.chenqiang.crypt;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.apache.commons.lang3.NotImplementedException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;

/**
 * 读写PEM文件的工具类。使用Bouncy Castle的工具类，支持PCKS#1和PCKS#8（含加密）。
 * 只有静态函数，不能实体化，不能继承。
 * 
 * @author CHEN Qiang
 *
 */
public final class PemUtils {
	private PemUtils() {}
	
	/**
	 * 将公钥以X509.1格式写入pem文件。
	 * 验证命令：openssl -in public.pem -noout -text -pubin
	 * @param publicKey
	 * @param writer
	 * @throws IOException
	 */
	public static void writePublicKeyToPem(PublicKey publicKey, Writer writer) throws IOException {
		try(JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
			pemWriter.writeObject(publicKey);
		}
	}
	
	/**
	 * 将私钥以PKCS#1格式写入pem文件
	 * 验证命令：openssl rsa -in private.pem -noout -text
	 * @param privateKey
	 * @param writer
	 * @throws IOException
	 */
	public static void writePrivateKeyToPkcs1Pem(PrivateKey privateKey, Writer writer) throws IOException {
		try(JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
			pemWriter.writeObject(privateKey);			
		}
	}
	
	/**
	 * 将私钥以PKCS#8格式写入pem文件
	 * 验证命令：openssl rsa -in private.pem -noout -text
	 * @param privateKey
	 * @param writer
	 * @throws IOException
	 */
	public static void writePrivateKeyToPkcs8Pem(PrivateKey privateKey, Writer writer) throws IOException {
		JcaPKCS8Generator gen = new JcaPKCS8Generator(privateKey, null);
		PemObject pemObject = gen.generate();
		try(JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
			pemWriter.writeObject(pemObject);
		}
	}
	
	/**
	 * 将私钥以PKCS#8格式加密写入pem文件
	 * 验证命令：openssl rsa -in private.pem -noout -text
	 * @param privateKey
	 * @param password
	 * @param writer
	 * @throws IOException
	 * @throws OperatorCreationException 
	 */
	public static void writePrivateKeyToPkcs8Pem(PrivateKey privateKey, char [] password, Writer writer) 
			throws IOException, OperatorCreationException {
		SecureRandom random = new SecureRandom();
		random.setSeed(System.currentTimeMillis());
		
		JceOpenSSLPKCS8EncryptorBuilder encryptorBuilder = new JceOpenSSLPKCS8EncryptorBuilder(PKCS8Generator.PBE_SHA1_3DES);
	    encryptorBuilder.setRandom(random);
	    encryptorBuilder.setPasssword(password);
	    OutputEncryptor oe = encryptorBuilder.build();
	    
	    JcaPKCS8Generator gen = new JcaPKCS8Generator(privateKey,oe);
	    PemObject pemObject = gen.generate();

		try(JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
			pemWriter.writeObject(pemObject);
		}
	}
	
	/**
	 * 调用Jca系列工具读出PEM文件内容，支持PKCS8加密。
	 * @param reader 读入流 
	 * @param password 密码
	 * @return KeyPair/PrivateKey/PublicKey等
	 * @throws OperatorCreationException 
	 * @throws IOException
	 * @throws PKCSException
	 * @throws NotImplementedException 其他尚未支持的类型
	 * 
	 * @see org.bouncycastle.openssl.PEMParser
	 */
	public static Object readPem(Reader reader, final char [] password) 
			throws OperatorCreationException, IOException, PKCSException  {
		Object obj = null;
		try(PEMParser pemParser = new PEMParser(reader)) {
			obj = pemParser.readObject();
		}		
		
		if(obj instanceof PEMKeyPair) {
			return new JcaPEMKeyConverter().getKeyPair((PEMKeyPair) obj);
		}
		else if(obj instanceof PrivateKeyInfo) {
			return new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) obj);
		}
		else if(obj instanceof SubjectPublicKeyInfo) {
			return new JcaPEMKeyConverter().getPublicKey((SubjectPublicKeyInfo) obj);
		}
		else if(obj instanceof PEMEncryptedKeyPair) {
			PEMDecryptorProvider decryptor =
					new JcePEMDecryptorProviderBuilder().build(password);
			PEMKeyPair keypair = ((PEMEncryptedKeyPair)obj).decryptKeyPair(decryptor);
			return new JcaPEMKeyConverter().getKeyPair(keypair);
		}
		else if(obj instanceof PKCS8EncryptedPrivateKeyInfo) {
			InputDecryptorProvider decryptor =
					new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password);			
			PrivateKeyInfo privateKeyInfo = ((PKCS8EncryptedPrivateKeyInfo)obj).decryptPrivateKeyInfo(decryptor);
			return new JcaPEMKeyConverter().getPrivateKey(privateKeyInfo);
		}
		else {
			throw new NotImplementedException("Not Implemented:" + obj.getClass().toString());
		}
	}
}
