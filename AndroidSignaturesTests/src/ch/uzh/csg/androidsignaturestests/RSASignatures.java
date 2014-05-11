package ch.uzh.csg.androidsignaturestests;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import android.util.Log;

public class RSASignatures {
	
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
		measureSHA1withRSA1024();
		measureSHA1withRSA2048();
		Log.d(TAG, "--SHA1 end--");
	}

	private static void measureSHA256() {
		Log.d(TAG, "--SHA256 start--");
		measureSHA256withRSA1024();
		measureSHA256withRSA2048();
		Log.d(TAG, "--SHA256 end--");
	}
	
	private static void measureSHA1withRSA1024() {
		Log.d(TAG, "start benchmark - SHA1withRSA1024");
		
		PrivateKey privateKey = generateNewKey(1024);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withRSA(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withRSA1024");
	}
	
	private static long SHA1withRSA(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		long start = System.currentTimeMillis();
		
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKey);
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		rsa.sign();
		
		return (start - System.currentTimeMillis());
	}
	
	private static void measureSHA1withRSA2048() {
		Log.d(TAG, "start benchmark - SHA1withRSA2048");
		
		PrivateKey privateKey = generateNewKey(2048);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withRSA(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withRSA2048");
	}
	
	private static void measureSHA256withRSA1024() {
		Log.d(TAG, "start benchmark - SHA256withRSA1024");
		
		PrivateKey privateKey = generateNewKey(1024);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withRSA(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withRSA1024");
	}
	
	private static long SHA256withRSA(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		long start = System.currentTimeMillis();
		
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(privateKey);
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		rsa.sign();
		
		return (start - System.currentTimeMillis());
	}
	
	private static void measureSHA256withRSA2048() {
		Log.d(TAG, "start benchmark - SHA256withRSA2048");
		
		PrivateKey privateKey = generateNewKey(2048);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withRSA(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withRSA1024");
	}
	
	private static PrivateKey generateNewKey(int keySize) {
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(keySize);
			return keyGen.generateKeyPair().getPrivate();
		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, "error", e);
			System.exit(0);
			return null;
		}
	}

}
