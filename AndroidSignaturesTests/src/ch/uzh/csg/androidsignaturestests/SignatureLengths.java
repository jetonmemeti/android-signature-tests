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
	private static final int NOF_RUNS = 10;
	
	private static int[] RSA_KEYSIZES = new int[] { 1024, 2048 };
	private static String[] ECC_ALGORITHMS = new String[] { "brainpoolp160r1", "brainpoolp224r1", "brainpoolp256r1", "brainpoolp384r1", "brainpoolp384t1" };
	
	public static void doTests() {
		Log.d(TAG, "----Signature Length start----");
		measureRSAs();
		measureECCs();
		Log.d(TAG, "----Signature Length end----");
	}
	
	private static void measureRSAs() {
		Log.d(TAG, "--RSA start--");
		for (int keySize : RSA_KEYSIZES) {
			measureRSA(keySize);
		}
		Log.d(TAG, "--RSA start--");
	}

	private static void measureECCs() {
		Log.d(TAG, "--ECC start--");
		for (String s : ECC_ALGORITHMS) {
			measureECC(s);
		}
		Log.d(TAG, "--ECC start--");
	}
	
	private static void measureRSA(int keySize) {
		Log.d(TAG, "RSA "+keySize);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<NOF_RUNS; i++) {
			try {
				if (i > 0)
					builder.append("\t");
				
				builder.append(measureRSALength(keySize));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				System.exit(0);
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

	private static void measureECC(String spec) {
		Log.d(TAG, "ECC "+spec);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<NOF_RUNS; i++) {
			try {
				if (i > 0)
					builder.append("\t");
				
				builder.append(measureECCLength(spec));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				System.exit(0);
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
