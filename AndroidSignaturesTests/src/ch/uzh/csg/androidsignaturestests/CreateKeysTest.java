package ch.uzh.csg.androidsignaturestests;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;

import android.util.Log;

public class CreateKeysTest {
	
	private static final String TAG = "CreateKeysTest";
	
	public static void doTests() {
		Log.d(TAG, "----CreateKeysTest start----");
		measureRSA();
		measureECC();
		Log.d(TAG, "----CreateKeysTest end----");
	}
	
	private static void measureRSA() {
		Log.d(TAG, "--RSA start--");
		measureCreate1024Keys();
		measureCreate2048Keys();
		Log.d(TAG, "--RSA end--");
	}
	
	private static void measureECC() {
		Log.d(TAG, "--ECC start--");
		measureCreate160ECCKeys();
		measureCreate224ECCKeys();
		Log.d(TAG, "--ECC end--");
	}
	
	private static void measureCreate1024Keys() {
		Log.d(TAG, "start benchmark - RSA-1024");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(createRSAKeys(1024));
			} catch (NoSuchAlgorithmException e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - RSA-1024");
	}
	
	private static long createRSAKeys(int keySize) throws NoSuchAlgorithmException {
		long start = System.currentTimeMillis();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(keySize);
		keyGen.generateKeyPair();
		return (System.currentTimeMillis() - start);
	}
	
	private static void measureCreate2048Keys() {
		Log.d(TAG, "start benchmark - RSA-2048");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(createRSAKeys(2048));
			} catch (NoSuchAlgorithmException e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - RSA-2048");
	}
	
	private static void measureCreate160ECCKeys() {
		Log.d(TAG, "start benchmark - ECC160");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(createECCKeys("brainpoolp160r1"));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - ECC160");
	}
	
	private static long createECCKeys(String spec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		long start = System.currentTimeMillis();
		
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(spec);
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "SC");
        g.initialize(ecSpec, new SecureRandom());
        g.generateKeyPair();
		
		return (System.currentTimeMillis() - start);
	}
	
	private static void measureCreate224ECCKeys() {
		Log.d(TAG, "start benchmark - ECC224");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(createECCKeys("brainpoolp224r1"));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - ECC224");
	}
	
}
