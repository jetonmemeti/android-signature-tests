package ch.uzh.csg.androidsignaturestests;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

import android.util.Log;

public class SignatureLengths {
	
	private static final String TAG = "SignatureLengths";
	
	private static final String PLAIN_TEXT = "Lorem ipsum dolor sit amet, consectetur adipiscing metus.";
	
	public static void doTests() {
		Log.d(TAG, "----Signature Length start----");
		measureRSA();
		measureECC();
		Log.d(TAG, "----Signature Length end----");
	}
	
	private static void measureRSA() {
		Log.d(TAG, "--RSA start--");
		measureRSA1024();
		measureRSA2048();
		Log.d(TAG, "--RSA start--");
	}

	private static void measureECC() {
		Log.d(TAG, "--ECC start--");
		measureECC160();
		measureECC224();
		Log.d(TAG, "--ECC start--");
	}

	private static void measureRSA1024() {
		try {
			Log.d(TAG, "RSA 1024");
			
			KeyPair keyPair = generateNewKey(1024);
			
			Signature rsa = Signature.getInstance("SHA256withRSA");
			rsa.initSign(keyPair.getPrivate());
			rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
			byte[] signature = rsa.sign();
			
			Log.d(TAG, "length: "+signature.length);
		} catch (Exception e) {
			Log.e(TAG, "error", e);
			System.exit(0);
		}
	}

	private static void measureRSA2048() {
		try {
			Log.d(TAG, "RSA 2048");
			
			KeyPair keyPair = generateNewKey(2048);
			
			Signature rsa = Signature.getInstance("SHA256withRSA");
			rsa.initSign(keyPair.getPrivate());
			rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
			byte[] signature = rsa.sign();
			
			Log.d(TAG, "length: "+signature.length);
		} catch (Exception e) {
			Log.e(TAG, "error", e);
			System.exit(0);
		}
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

	private static void measureECC160() {
		try {
			Log.d(TAG, "ECC 160");
			
			KeyPair keyPair = generateNewKey("brainpoolp160r1");
			
			Signature ecdsaSign = Signature.getInstance("SHA1withECDSA", "SC");
	        ecdsaSign.initSign(keyPair.getPrivate());
	        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
	        byte[] signature = ecdsaSign.sign();
			
	        Log.d(TAG, "length: "+signature.length);
		} catch (Exception e) {
			Log.e(TAG, "error", e);
			System.exit(0);
		}
	}

	private static void measureECC224() {
		try {
			Log.d(TAG, "ECC 224");
			
			KeyPair keyPair = generateNewKey("brainpoolp224r1");
			
			Signature ecdsaSign = Signature.getInstance("SHA1withECDSA", "SC");
	        ecdsaSign.initSign(keyPair.getPrivate());
	        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
	        byte[] signature = ecdsaSign.sign();
			
	        Log.d(TAG, "length: "+signature.length);
		} catch (Exception e) {
			Log.e(TAG, "error", e);
			System.exit(0);
		}
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
