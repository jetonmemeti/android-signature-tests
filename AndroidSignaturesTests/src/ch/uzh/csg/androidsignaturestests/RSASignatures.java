package ch.uzh.csg.androidsignaturestests;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import android.util.Log;

public class RSASignatures {
	
	private static final String TAG = "RSASignatures";
	private static final String PLAIN_TEXT = "lorem ipsum blablabla";
	
	private static PrivateKey privateKey1024 = null;
	private static PublicKey publicKey1024 = null;
	private static PrivateKey privateKey2048 = null;
	private static PublicKey publicKey2048 = null;
	
	public static final void doTests() {
		KeyPair keyPair1 = generateNewKey(1024);
		privateKey1024 = keyPair1.getPrivate();
		publicKey1024 = keyPair1.getPublic();
		
		KeyPair keyPair2 = generateNewKey(2048);
		privateKey2048 = keyPair2.getPrivate();
		publicKey2048 = keyPair2.getPublic();
		
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
		measureSHA1withRSA1024sign();
		measureSHA1withRSA2048sign();
		Log.d(TAG, "-SHA1 sign end-");
	}
	
	private static void measureSHA1verify() {
		Log.d(TAG, "-SHA1 verify start-");
		measureSHA1withRSA1024verify();
		measureSHA1withRSA2048verify();
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
		measureSHA256withRSA1024sign();
		measureSHA256withRSA2048sign();
		Log.d(TAG, "-SHA256 sign end-");
	}
	
	private static void measureSHA26verify() {
		Log.d(TAG, "-SHA256 verify start-");
		measureSHA256withRSA1024verify();
		measureSHA256withRSA2048verify();
		Log.d(TAG, "-SHA256 verify end-");
	}

	private static void measureSHA1withRSA1024sign() {
		Log.d(TAG, "start benchmark - SHA1withRSA1024 sign");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withRSAsign(privateKey1024));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withRSA1024 sign");
	}
	
	private static void measureSHA1withRSA2048sign() {
		Log.d(TAG, "start benchmark - SHA1withRSA2048 sign");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withRSAsign(privateKey2048));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withRSA2048 sign");
	}
	

	private static void measureSHA1withRSA1024verify() {
		Log.d(TAG, "start benchmark - SHA1withRSA1024 verify");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withRSAverify(privateKey1024, publicKey1024));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withRSA1024 verify");
	}

	private static void measureSHA1withRSA2048verify() {
		Log.d(TAG, "start benchmark - SHA1withRSA2048 verify");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA1withRSAverify(privateKey2048, publicKey2048));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withRSA2048 verify");
	}
	
	private static long SHA1withRSAsign(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		long start = System.currentTimeMillis();
		
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKey);
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		rsa.sign();
		
		return (start - System.currentTimeMillis());
	}
	
	private static long SHA1withRSAverify(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKey);
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		byte[] signature = rsa.sign();
		
		long start = System.currentTimeMillis();
		
		Signature rsa2 = Signature.getInstance("SHA1withRSA");
		rsa2.initVerify(publicKey);
		rsa2.update(PLAIN_TEXT.getBytes("UTF-8"));
		boolean verify = rsa2.verify(signature);
		
		if (!verify) {
			Log.e(TAG, "signature not ok!");
			System.exit(0);
		}
		
		return (start - System.currentTimeMillis());
	}
	
	private static void measureSHA256withRSA1024sign() {
		Log.d(TAG, "start benchmark - SHA256withRSA1024 sign");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withRSAsign(privateKey1024));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withRSA1024 sign");
	}
	
	private static void measureSHA256withRSA2048sign() {
		Log.d(TAG, "start benchmark - SHA256withRSA2048 sign");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withRSAsign(privateKey2048));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withRSA1024 sign");
	}

	private static void measureSHA256withRSA1024verify() {
		Log.d(TAG, "start benchmark - SHA256withRSA1024 verify");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withRSAverify(privateKey1024, publicKey1024));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withRSA1024 verify");
	}

	private static void measureSHA256withRSA2048verify() {
		Log.d(TAG, "start benchmark - SHA256withRSA2048 verify");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withRSAverify(privateKey2048, publicKey2048));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withRSA2048 verify");
	}
	
	private static long SHA256withRSAsign(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		long start = System.currentTimeMillis();
		
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(privateKey);
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		rsa.sign();
		
		return (start - System.currentTimeMillis());
	}
	
	private static long SHA256withRSAverify(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(privateKey);
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		byte[] signature = rsa.sign();
		
		long start = System.currentTimeMillis();
		
		Signature rsa2 = Signature.getInstance("SHA256withRSA");
		rsa2.initVerify(publicKey);
		rsa2.update(PLAIN_TEXT.getBytes("UTF-8"));
		boolean verify = rsa2.verify(signature);
		
		if (!verify) {
			Log.e(TAG, "signature not ok!");
			System.exit(0);
		}
		
		return (start - System.currentTimeMillis());
	}
	
	private static KeyPair generateNewKey(int keySize) {
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(keySize);
			return keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, "error", e);
			System.exit(0);
			return null;
		}
	}

}
