package me.chenqiang.cert;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Test;

import me.chenqiang.crypt.asymmetric.RSAFunctions;

public class CertificateTestSuite {
	protected static final Random RANDOM;
	static {
		Security.addProvider(new BouncyCastleProvider());
		try {
			RANDOM = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new AssertionError(e);
		}
	}

	protected File dir;
	protected String keyStorePassword;	
	
	@Before
	public void init() {
		File tmpdir = new File(System.getProperty("java.io.tmpdir"));
		File location = new File(tmpdir, "CertTest");
		if(location.exists()) {
			if(!location.isDirectory()) {
				throw new AssertionError(String.format("Path exists and is not a directory. %s", location.getAbsolutePath()));
			}
		}
		else {
			location.mkdirs();
		}
		this.dir = location;
		System.out.println(this.dir.getAbsolutePath());
		this.keyStorePassword = "{2019CertTest]";
		System.out.println(this.keyStorePassword);
	}
	
	protected class CertificateSubject {
		public CertificateSubject(X500Name dn) {
			this.dn = dn;

			KeyPair kp = RSAFunctions.generateKeyPair(2048);
			this.privateKey = kp.getPrivate();
			this.publicKey = kp.getPublic();
		}
		
		private X500Name dn;
		private PrivateKey privateKey;
		private PublicKey publicKey;
		public X500Name getDn() {
			return dn;
		}
		public PrivateKey getPrivateKey() {
			return privateKey;
		}
		public PublicKey getPublicKey() {
			return publicKey;
		}		
	}
	
	protected CertificateSubject rootCASubject = 
			new CertificateSubject(X500NameStructure.build("Root CA", "TestCase", "CA Authority", null, "Beijing", "CN"));
	protected CertificateSubject intermediateCASubject = 
			new CertificateSubject(X500NameStructure.build("Intermediate CA", "TestCase", "CA Authority", null, "Beijing", "CN"));
	protected CertificateSubject endUserSubject = 
			new CertificateSubject(X500NameStructure.build("End User", "TestCase", "Client", null, "Beijing", "CN"));
	
	protected Date [] createValidDatePeriod(int months) {
		LocalDate now = LocalDate.now();
		Date notBefore = Date.from(now.atStartOfDay(ZoneId.systemDefault()).toInstant());
		Date notAfter = Date.from(now.plusMonths(months).atStartOfDay(ZoneId.systemDefault()).toInstant());
		return new Date[] {notBefore, notAfter};
	}
	
	protected void createRootCA() 
			throws CertificateException, OperatorCreationException, KeyStoreException, 
			FileNotFoundException, IOException, NoSuchAlgorithmException {
		Date [] period = this.createValidDatePeriod(24);
		X500Name rootName = this.rootCASubject.getDn();
		JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
				rootName, BigInteger.probablePrime(32, RANDOM),
				period[0], period[1], rootName, this.rootCASubject.getPublicKey());
		cb.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));  
		cb.addExtension(Extension.basicConstraints, false, new BasicConstraints(true));   
		
		cb.addExtension(Extension.subjectKeyIdentifier, false, 
				new JcaX509ExtensionUtils().createSubjectKeyIdentifier(this.rootCASubject.getPublicKey()));
		
		
		ContentSigner signer = new JcaContentSignerBuilder(CertificateConsts.SHA256WITHRSA)
				.build(this.rootCASubject.getPrivateKey());
		X509CertificateHolder holder = cb.build(signer);
		Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
		try(FileOutputStream fos = new FileOutputStream(new File(this.dir, "ca.cer"))){
			fos.write(cert.getEncoded());
		}		
		
		KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(null, null);
		ks.setKeyEntry("root", this.rootCASubject.getPrivateKey(), "root".toCharArray(), new Certificate[] {cert});
		ks.setCertificateEntry("cacert", cert);
		try(FileOutputStream fos = new FileOutputStream(new File(this.dir, "ca.pfx"))){
			ks.store(fos, this.keyStorePassword.toCharArray());
		}
	}
	
	protected void createIntermediateCA() 
			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, 
			FileNotFoundException, IOException, CertificateException, OperatorCreationException {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try(FileInputStream fin = new FileInputStream(new File(this.dir, "ca.pfx"))){
			ks.load(fin, this.keyStorePassword.toCharArray());
		}
		X509Certificate rootCert = (X509Certificate)ks.getCertificate("cacert");
		
		Date [] period = this.createValidDatePeriod(3);
		PublicKey publicKey = this.intermediateCASubject.getPublicKey();
		JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(
				this.rootCASubject.getDn(), BigInteger.probablePrime(32, RANDOM), period[0], period[1], 
				this.intermediateCASubject.getDn(), publicKey);
		cb.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign));  
		cb.addExtension(Extension.basicConstraints, true, new BasicConstraints(2)); 
		
		cb.addExtension(Extension.subjectKeyIdentifier, false, 
				new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey));
		cb.addExtension(Extension.authorityKeyIdentifier, false,
				new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(rootCert.getPublicKey()));
//						new X509CertificateHolder(rootCert.getEncoded())));
		
		ContentSigner signer = new JcaContentSignerBuilder(CertificateConsts.SHA256WITHRSA)
				.build(this.rootCASubject.getPrivateKey());
		
		X509CertificateHolder holder = cb.build(signer);
		Certificate intCert = new JcaX509CertificateConverter().getCertificate(holder);
		try(FileOutputStream fos = new FileOutputStream(new File(this.dir, "intermediate.cer"))){
			fos.write(intCert.getEncoded());
		}
		
		
		ks.setKeyEntry("intermediate", this.intermediateCASubject.getPrivateKey(), 
				"intermediate".toCharArray(), new Certificate[] {intCert});

		try(FileOutputStream fos = new FileOutputStream(new File(this.dir, "ca.pfx"))){
			ks.store(fos, this.keyStorePassword.toCharArray());
		}
	}
	
	protected void createEndUserCertificationRequest() throws OperatorCreationException, FileNotFoundException, IOException {
		ContentSigner signGen = new JcaContentSignerBuilder(CertificateConsts.SHA256WITHRSA)
				.build(this.endUserSubject.getPrivateKey());
		PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
				this.endUserSubject.getDn(), this.endUserSubject.getPublicKey());
		PKCS10CertificationRequest csr = builder.build(signGen);
		try(FileOutputStream fos = new FileOutputStream(new File(this.dir, "enduser.csr"))){
			fos.write(csr.getEncoded());
		}
	}
	
	protected void createEndUserCertificate() 
			throws NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException, 
			FileNotFoundException, IOException, CertificateException, OperatorCreationException {
		PKCS10CertificationRequest csr = new PKCS10CertificationRequest(
				Files.readAllBytes(new File(this.dir, "enduser.csr").toPath()));
		
		KeyStore ks = KeyStore.getInstance("PKCS12");
		try(FileInputStream fin = new FileInputStream(new File(this.dir, "ca.pfx"))){
			ks.load(fin, this.keyStorePassword.toCharArray());
		}		
		PrivateKeyEntry entry = (PrivateKeyEntry)ks.getEntry("intermediate", 
				new KeyStore.PasswordProtection("intermediate".toCharArray()));
		PrivateKey caKey = entry.getPrivateKey();
		X509Certificate caCert = (X509Certificate)entry.getCertificate();
		
		Date [] period = this.createValidDatePeriod(1);
		X509v3CertificateBuilder cb = new X509v3CertificateBuilder(
				JcaX500NameUtil.getSubject(caCert), BigInteger.probablePrime(32, RANDOM), period[0], period[1], 
				csr.getSubject(), csr.getSubjectPublicKeyInfo());
		cb.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));  
		cb.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
		
		cb.addExtension(Extension.subjectKeyIdentifier, false, 
				new JcaX509ExtensionUtils().createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));
		cb.addExtension(Extension.authorityKeyIdentifier, false,
				new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert));
				
		ContentSigner signer = new JcaContentSignerBuilder(CertificateConsts.SHA256WITHRSA).build(caKey);
		X509CertificateHolder holder = cb.build(signer);
		Certificate eu = new JcaX509CertificateConverter().getCertificate(holder);
		try(FileOutputStream fos = new FileOutputStream(new File(this.dir, "enduser.cer"))){
			fos.write(eu.getEncoded());
		}
	}
	
	public void verifyEndUser() throws Exception {
		X509Certificate enduser = null;
		try(FileInputStream fin = new FileInputStream(new File(this.dir, "enduser.cer"))){
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			enduser = (X509Certificate)fact.generateCertificate(fin);
		}
		
		X509Certificate intermediate = null;
		try(FileInputStream fin = new FileInputStream(new File(this.dir, "intermediate.cer"))){
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			intermediate = (X509Certificate)fact.generateCertificate(fin);
		}
		
		enduser.verify(intermediate.getPublicKey());
		
		X509CertSelector selector = new X509CertSelector();
		selector.setCertificate(enduser);
		
		KeyStore anchors = KeyStore.getInstance("PKCS12");
		try(FileInputStream fin = new FileInputStream(new File(this.dir, "ca.pfx"))){
			anchors.load(fin, this.keyStorePassword.toCharArray());
		}
		
		PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, selector);
		CertStoreParameters intermediates = new CollectionCertStoreParameters(Arrays.asList(intermediate));
		params.addCertStore(CertStore.getInstance("Collection", intermediates));
		//!!!!!
		params.setRevocationEnabled(false); 
		CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");		
		CertPathBuilderResult result = builder.build(params);
		CertPath path = result.getCertPath();
		for(Certificate cert : path.getCertificates()) {
			System.out.println(((X509Certificate)cert).getSubjectDN().toString());
		}		
	}
	
	@Test
	public void testCert() throws Exception {
		this.createRootCA();
		this.createIntermediateCA();
		this.createEndUserCertificationRequest();
		this.createEndUserCertificate();
		this.verifyEndUser();
	}
	
}
