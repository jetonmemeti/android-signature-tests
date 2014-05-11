package ch.uzh.csg.androidsignaturestests;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import android.util.Log;

public class ECCSignatures {
	
	private static final String TAG = "RSASignatures";
	private static final String PLAIN_TEXT = "lorem ipsum blablabla";
	
	public static final void doTests() {
		Log.d(TAG, "----RSASignatures start----");
		measureSHA1();
		measureSHA256();
		Log.d(TAG, "----RSASignatures end----");
	}

	private static void measureSHA1() {
		Log.d(TAG, "--SHA1 start--");
		measureSHA1withECDSA160();
		measureSHA1withECDSA224();
		Log.d(TAG, "--SHA1 end--");
	}

	private static void measureSHA256() {
		Log.d(TAG, "--SHA256 start--");
		measureSHA256withECDSA160();
		measureSHA256withECDSA224();
		Log.d(TAG, "--SHA256 end--");
	}
	
	private static void measureSHA1withECDSA160() {
		Log.d(TAG, "start benchmark - SHA1withECDSA160");
		
		PrivateKey privateKey = generateNewKey("brainpoolp160r1");
        
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withECDSA(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withECDSA160");
	}
	
	private static long SHA1withECDSA(PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		long start = System.currentTimeMillis();
		
		Signature ecdsaSign = Signature.getInstance("SHA1withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
        ecdsaSign.sign();
        
        return (start - System.currentTimeMillis());
	}
	
	private static void measureSHA1withECDSA224() {
		Log.d(TAG, "start benchmark - SHA1withECDSA224");
		
		PrivateKey privateKey = generateNewKey("brainpoolp224r1");
        
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withECDSA(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withECDSA224");
	}
	
	private static void measureSHA256withECDSA160() {
		Log.d(TAG, "start benchmark - SHA256withECDSA160");
		
		PrivateKey privateKey = generateNewKey("brainpoolp160r1");
        
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withECDSA(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withECDSA160");
	}
	
	private static long SHA256withECDSA(PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		long start = System.currentTimeMillis();
		
		Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
        ecdsaSign.sign();
        
        return (start - System.currentTimeMillis());
	}
	
	private static void measureSHA256withECDSA224() {
		Log.d(TAG, "start benchmark - SHA256withECDSA224");
		
		PrivateKey privateKey = generateNewKey("brainpoolp224r1");
        
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withECDSA(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withECDSA224");
	}
	
	private static PrivateKey generateNewKey(String spec) {
		try {
			ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(spec);
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
			keyGen.initialize(ecSpec, new SecureRandom());
			return keyGen.generateKeyPair().getPrivate();
		} catch (Exception e) {
			Log.e(TAG, "error", e);
			System.exit(0);
			return null;
		}
	}

}
