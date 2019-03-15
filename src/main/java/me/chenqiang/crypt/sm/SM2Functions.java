package me.chenqiang.crypt.sm;


import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import me.chenqiang.crypt.SecureRandomFunctions;

public class SM2Functions {
	private static final Logger LOGGER = LoggerFactory.getLogger(SM2Functions.class);
	protected static ECDomainParameters generateDomainParameters() {
		X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
		return new ECDomainParameters(sm2ECParameters.getCurve(),
                sm2ECParameters.getG(), sm2ECParameters.getN());
	}
	
	public static AsymmetricCipherKeyPair generateKeyPair() {
        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(generateDomainParameters(), SecureRandomFunctions.getStrongRandom()));
        return keyPairGenerator.generateKeyPair();
	}
	
	public static Pair<ECPublicKeyParameters, ECPrivateKeyParameters> generateCastedKeyPair() {
		AsymmetricCipherKeyPair kp = generateKeyPair();
        return Pair.of((ECPublicKeyParameters)kp.getPublic(), (ECPrivateKeyParameters)kp.getPrivate());
	}

	public static String getPublicKeyString(ECPublicKeyParameters key, boolean compressed, boolean withFlag04) {
		String res = Hex.toHexString(key.getQ().getEncoded(compressed));
		if(!compressed && !withFlag04) {
			res = res.substring(2);
		}
		LOGGER.debug(res);
		return res;
	}
	
	public static String getPublicKeyString(ECPublicKeyParameters key, boolean compressed) {
		return getPublicKeyString(key, compressed, false);
	}
	
	public static String getPublicKeyString(ECPublicKeyParameters key) {
		return getPublicKeyString(key, false, false);
	}
	
	public static String getPrivateKeyString(ECPrivateKeyParameters key) {
		String res = key.getD().toString(16);
		LOGGER.debug(res);
		return res;
	}
	
	public static Pair<String, String> generateEncodedKeyPair() {
		Pair<ECPublicKeyParameters, ECPrivateKeyParameters> kp = generateCastedKeyPair();
        return Pair.of(
        		getPublicKeyString(kp.getLeft(), false, false),
        		getPrivateKeyString(kp.getRight()));
	}
}
