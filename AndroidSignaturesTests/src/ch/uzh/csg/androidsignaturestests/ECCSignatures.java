package ch.uzh.csg.androidsignaturestests;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

import android.util.Log;

public class ECCSignatures {
	
	private static final String TAG = "ECCSignatures";
	private static final String PLAIN_TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing metus.";
	
	private static final int NOF_RUNS = 10;
	
	private static String[] ECC_ALGORITHMS = new String[] { "brainpoolp160r1", "brainpoolp224r1", "brainpoolp256r1", "brainpoolp384r1", "brainpoolp384t1" };
	private static KeyPair[] KEY_PAIRS = new KeyPair[ECC_ALGORITHMS.length];
	private static String[] SHA_ALGORITHMS = new String[] { "SHA1withECDSA", "SHA256withECDSA"};
	
	public static final void doTests() {
		for (int i=0; i<ECC_ALGORITHMS.length; i++) {
			KEY_PAIRS[i] = generateNewKey(ECC_ALGORITHMS[i]);
		}
		Log.d(TAG, "----ECCSignatures start----");
		for (int i=0; i<SHA_ALGORITHMS.length; i++) {
			Log.d(TAG, "--"+SHA_ALGORITHMS[i]+" start--");
			for (int j=0; j<ECC_ALGORITHMS.length; j++) {
				measureSHAsign(ECC_ALGORITHMS[j], SHA_ALGORITHMS[i], KEY_PAIRS[j].getPrivate());
				measureSHAverify(ECC_ALGORITHMS[j], SHA_ALGORITHMS[i], KEY_PAIRS[j].getPrivate(), KEY_PAIRS[j].getPublic());
			}
			Log.d(TAG, "--"+SHA_ALGORITHMS[i]+" end--");
		}
		Log.d(TAG, "----ECCSignatures end----");
	}
	
	private static void measureSHAsign(String spec, String signatureAlgorithm, PrivateKey privateKey) {
		Log.d(TAG, "start benchmark - "+signatureAlgorithm+" sign - ECC "+spec);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<NOF_RUNS; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHAwithECDSAsign(signatureAlgorithm, privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				System.exit(0);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - "+signatureAlgorithm+" sign - ECC "+spec);
	}

	private static long SHAwithECDSAsign(String signatureAlgorithm, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		long start = System.currentTimeMillis();
		
		Signature ecdsaSign = Signature.getInstance(signatureAlgorithm);
		ecdsaSign.initSign(privateKey);
		ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
		ecdsaSign.sign();
		
		return (System.currentTimeMillis() - start);
	}
	
	private static void measureSHAverify(String spec, String signatureAlgorithm, PrivateKey privateKey, PublicKey publicKey) {
		Log.d(TAG, "start benchmark - "+signatureAlgorithm+" verify - ECC "+spec);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<NOF_RUNS; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHAwithECDSAverify(signatureAlgorithm, privateKey, publicKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				System.exit(0);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - "+signatureAlgorithm+" verify - ECC "+spec);
	}
	
	private static long SHAwithECDSAverify(String signatureAlgorithm, PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		Signature ecdsaSign = Signature.getInstance(signatureAlgorithm);
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
		
		long start = System.currentTimeMillis();
		
		Signature ecdsaSign2 = Signature.getInstance(signatureAlgorithm);
		ecdsaSign2.initVerify(publicKey);
        ecdsaSign2.update(PLAIN_TEXT.getBytes("UTF-8"));
        boolean verify = ecdsaSign2.verify(signature);
        
        if (!verify) {
        	Log.e(TAG, "signature not ok!");
			System.exit(0);
        }
        
        return (System.currentTimeMillis() - start);
	}

	private static KeyPair generateNewKey(String spec) {
		try {
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(spec);
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "SC");
			keyGen.initialize(ecSpec, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (Exception e) {
			Log.e(TAG, "error", e);
			System.exit(0);
			return null;
		}
	}

}
