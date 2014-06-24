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
	private static final String PLAIN_TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing metus.";
	
	private static final int NOF_RUNS = 10;
	
	private static int[] RSA_KEYSIZES = new int[] { 1024, 2048 };
	private static KeyPair[] KEY_PAIRS = new KeyPair[RSA_KEYSIZES.length];
	private static String[] SHA_ALGORITHMS = new String[] { "SHA1withRSA", "SHA256withRSA"};
	
	public static final void doTests() {
		for (int i=0; i<RSA_KEYSIZES.length; i++) {
			KEY_PAIRS[i] = generateNewKey(RSA_KEYSIZES[i]);
		}
		Log.d(TAG, "----RSASignatures start----");
		for (int i=0; i<SHA_ALGORITHMS.length; i++) {
			Log.d(TAG, "--"+SHA_ALGORITHMS[i]+" start--");
			for (int j=0; j<RSA_KEYSIZES.length; j++) {
				measureSHAsign(RSA_KEYSIZES[j], SHA_ALGORITHMS[i], KEY_PAIRS[j].getPrivate());
				measureSHAverify(RSA_KEYSIZES[j], SHA_ALGORITHMS[i], KEY_PAIRS[j].getPrivate(), KEY_PAIRS[j].getPublic());
			}
			Log.d(TAG, "--"+SHA_ALGORITHMS[i]+" end--");
		}
		Log.d(TAG, "----RSASignatures end----");
	}

	private static void measureSHAsign(int keySize, String signatureAlgorithm, PrivateKey privateKey) {
		Log.d(TAG, "start benchmark - "+signatureAlgorithm+" sign - RSA "+keySize);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<NOF_RUNS; i++) {
			try {
				if (i > 0)
					builder.append("\t");
				
				builder.append(SHAwithRSAsign(signatureAlgorithm, privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				System.exit(0);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - "+signatureAlgorithm+" sign - RSA "+keySize);
	}
	
	private static long SHAwithRSAsign(String signatureAlgorithm, PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		long start = System.currentTimeMillis();
		
		Signature rsa = Signature.getInstance(signatureAlgorithm);
		rsa.initSign(privateKey);
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		rsa.sign();
		
		return (System.currentTimeMillis() - start);
	}

	private static void measureSHAverify(int keySize, String signatureAlgorithm, PrivateKey privateKey, PublicKey publicKey) {
		Log.d(TAG, "start benchmark - "+signatureAlgorithm+" verify - RSA "+keySize);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<NOF_RUNS; i++) {
			try {
				if (i > 0)
					builder.append("\t");
				
				builder.append(SHAwithRSAverify(signatureAlgorithm, privateKey, publicKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				System.exit(0);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - "+signatureAlgorithm+" verify - RSA "+keySize);
	}
	
	private static long SHAwithRSAverify(String signatureAlgorithm, PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		Signature rsa = Signature.getInstance(signatureAlgorithm);
		rsa.initSign(privateKey);
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		byte[] signature = rsa.sign();
		
		long start = System.currentTimeMillis();
		
		Signature rsa2 = Signature.getInstance(signatureAlgorithm);
		rsa2.initVerify(publicKey);
		rsa2.update(PLAIN_TEXT.getBytes("UTF-8"));
		boolean verify = rsa2.verify(signature);
		
		if (!verify) {
			Log.e(TAG, "signature not ok!");
			System.exit(0);
		}
		
		return (System.currentTimeMillis() - start);
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
