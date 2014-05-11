package ch.uzh.csg.androidsignaturestests;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

import android.util.Log;

public class ECCSignatures {
	
	private static final String TAG = "RSASignatures";
	private static final String PLAIN_TEXT = "lorem ipsum blablabla";
	
	private static PrivateKey privateKey160 = null;
	private static PublicKey publicKey160 = null;
	private static PrivateKey privateKey224 = null;
	private static PublicKey publicKey224 = null;
	
	public static final void doTests() {
		KeyPair keyPair1 = generateNewKey("brainpoolp160r1");
		privateKey160 = keyPair1.getPrivate();
		publicKey160 = keyPair1.getPublic();
		
		KeyPair keyPair2 = generateNewKey("brainpoolp224r1");
		privateKey224 = keyPair2.getPrivate();
		publicKey224 = keyPair2.getPublic();
		
		Log.d(TAG, "----RSASignatures start----");
		measureSHA1();
		measureSHA256();
		Log.d(TAG, "----RSASignatures end----");
	}

	private static void measureSHA1() {
		Log.d(TAG, "--SHA1 start--");
		measureSHA1sign();
		measureSHA1verify();
		Log.d(TAG, "--SHA1 end--");
	}

	private static void measureSHA1sign() {
		Log.d(TAG, "-SHA1 sign start-");
		measureSHA1withECDSA160sign();
		measureSHA1withECDSA224sign();
		Log.d(TAG, "-SHA1 sign end-");
	}
	
	private static void measureSHA1verify() {
		Log.d(TAG, "-SHA1 verify start-");
		measureSHA1withECDSA160verify();
		measureSHA1withECDSA224verify();
		Log.d(TAG, "-SHA1 verify end-");
	}

	private static void measureSHA256() {
		Log.d(TAG, "--SHA256 start--");
		measureSHA26sign();
		measureSHA26verify();
		Log.d(TAG, "--SHA256 end--");
	}
	
	private static void measureSHA26sign() {
		Log.d(TAG, "-SHA256 sign start-");
		measureSHA256withECDSA160sign();
		measureSHA256withECDSA224sign();
		Log.d(TAG, "-SHA256 sign end-");
	}
	
	private static void measureSHA26verify() {
		Log.d(TAG, "-SHA256 verify start-");
		measureSHA256withECDSA160verify();
		measureSHA256withECDSA224verify();
		Log.d(TAG, "-SHA256 verify end-");
	}

	private static void measureSHA1withECDSA160sign() {
		Log.d(TAG, "start benchmark - SHA1withECDSA160 sign");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withECDSAsign(privateKey160));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withECDSA160 sign");
	}
	
	private static void measureSHA1withECDSA224sign() {
		Log.d(TAG, "start benchmark - SHA1withECDSA224 sign");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withECDSAsign(privateKey224));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withECDSA224 sign");
	}

	private static void measureSHA1withECDSA160verify() {
		Log.d(TAG, "start benchmark - SHA1withECDSA160 verify");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withECDSAverify(privateKey160, publicKey160));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withECDSA160 verify");
	}

	private static void measureSHA1withECDSA224verify() {
		Log.d(TAG, "start benchmark - SHA1withECDSA224 verify");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withECDSAverify(privateKey224, publicKey224));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withECDSA224 verify");
	}
	
	private static long SHA1withECDSAsign(PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		long start = System.currentTimeMillis();
		
		Signature ecdsaSign = Signature.getInstance("SHA1withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
        ecdsaSign.sign();
        
        return (System.currentTimeMillis() - start);
	}
	
	private static long SHA1withECDSAverify(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		Signature ecdsaSign = Signature.getInstance("SHA1withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
		
		long start = System.currentTimeMillis();
		
		Signature ecdsaSign2 = Signature.getInstance("SHA1withECDSA", "BC");
		ecdsaSign2.initVerify(publicKey);
        ecdsaSign2.update(PLAIN_TEXT.getBytes("UTF-8"));
        boolean verify = ecdsaSign2.verify(signature);
        
        if (!verify) {
        	Log.e(TAG, "signature not ok!");
			System.exit(0);
        }
        
        return (System.currentTimeMillis() - start);
	}
	
	private static void measureSHA256withECDSA160sign() {
		Log.d(TAG, "start benchmark - SHA256withECDSA160 sign");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withECDSAsign(privateKey160));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withECDSA160 sign");
	}
	
	private static void measureSHA256withECDSA224sign() {
		Log.d(TAG, "start benchmark - SHA256withECDSA224 sign");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withECDSAsign(privateKey224));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withECDSA224 sign");
	}
	
	private static void measureSHA256withECDSA160verify() {
		Log.d(TAG, "start benchmark - SHA256withECDSA160 verify");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withECDSAverify(privateKey160, publicKey160));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withECDSA160 verify");
	}

	private static void measureSHA256withECDSA224verify() {
		Log.d(TAG, "start benchmark - SHA256withECDSA224 verify");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withECDSAverify(privateKey224, publicKey224));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withECDSA224 verify");
	}
	
	private static long SHA256withECDSAsign(PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		long start = System.currentTimeMillis();
		
		Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
		ecdsaSign.initSign(privateKey);
		ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
		ecdsaSign.sign();
		
		return (System.currentTimeMillis() - start);
	}
	
	private static long SHA256withECDSAverify(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		Signature ecdsaSign = Signature.getInstance("SHA256withECDSA", "BC");
        ecdsaSign.initSign(privateKey);
        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
		
		long start = System.currentTimeMillis();
		
		Signature ecdsaSign2 = Signature.getInstance("SHA256withECDSA", "BC");
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
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDSA", "BC");
			keyGen.initialize(ecSpec, new SecureRandom());
			return keyGen.generateKeyPair();
		} catch (Exception e) {
			Log.e(TAG, "error", e);
			System.exit(0);
			return null;
		}
	}

}
