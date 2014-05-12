package ch.uzh.csg.androidsignaturestests;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

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
		measureECC384();
		Log.d(TAG, "--ECC start--");
	}

	private static void measureRSA1024() {
		Log.d(TAG, "RSA 1024");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(measureRSALength(1024));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
	}

	private static void measureRSA2048() {
		Log.d(TAG, "RSA 2048");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(measureRSALength(2048));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
	}
	
	private static int measureRSALength(int keySize) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		KeyPair keyPair = generateNewKey(keySize);
		
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(keyPair.getPrivate());
		rsa.update(PLAIN_TEXT.getBytes("UTF-8"));
		byte[] signature = rsa.sign();
		
		return signature.length;
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
		Log.d(TAG, "ECC 160");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<20; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(measureECCLength("brainpoolp160r1"));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
	}
	
	private static void measureECC224() {
		Log.d(TAG, "ECC 224");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<20; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(measureECCLength("brainpoolp224r1"));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
	}
	
	private static void measureECC384() {
		Log.d(TAG, "ECC 384");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<20; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(measureECCLength("brainpoolp384t1"));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
	}
	
	private static int measureECCLength(String spec) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
		KeyPair keyPair = generateNewKey(spec);
		
		Signature ecdsaSign = Signature.getInstance("SHA256ithECDSA");
        ecdsaSign.initSign(keyPair.getPrivate());
        ecdsaSign.update(PLAIN_TEXT.getBytes("UTF-8"));
        byte[] signature = ecdsaSign.sign();
        
        return signature.length;
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
