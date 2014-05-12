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
	
	private static final int NOF_RUNS = 10;
	
	private static int[] RSA_KEYSIZES = new int[] { 1024, 2048 };
	private static String[] ECC_ALGORITHMS = new String[] { "brainpoolp160r1", "brainpoolp224r1", "brainpoolp256r1", "brainpoolp384r1", "brainpoolp384t1" };
	
	public static void doTests() {
		Log.d(TAG, "----CreateKeysTest start----");
		measureRSAs();
		measureECCs();
		Log.d(TAG, "----CreateKeysTest end----");
	}
	
	private static void measureRSAs() {
		Log.d(TAG, "--RSA start--");
		for (int i : RSA_KEYSIZES) {
			measureRSA(i);
		}
		Log.d(TAG, "--RSA end--");
	}
	
	private static void measureECCs() {
		Log.d(TAG, "--ECC start--");
		for (String s : ECC_ALGORITHMS) {
			measureECC(s);
		}
		Log.d(TAG, "--ECC end--");
	}
	
	private static void measureRSA(int keySize) {
		Log.d(TAG, "start benchmark - RSA"+keySize);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<NOF_RUNS; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(createRSAKeys(keySize));
			} catch (NoSuchAlgorithmException e) {
				Log.e(TAG, "error", e);
				System.exit(0);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - RSA"+keySize);
	}

	private static long createRSAKeys(int keySize) throws NoSuchAlgorithmException {
		long start = System.currentTimeMillis();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(keySize);
		keyGen.generateKeyPair();
		return (System.currentTimeMillis() - start);
	}
	

	private static void measureECC(String spec) {
		Log.d(TAG, "start benchmark - ECC - "+spec);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<NOF_RUNS; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(createECCKeys(spec));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				System.exit(0);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - ECC - "+spec);
	}
	
	private static long createECCKeys(String spec) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		long start = System.currentTimeMillis();
		
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(spec);
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA");
        g.initialize(ecSpec, new SecureRandom());
        g.generateKeyPair();
		
		return (System.currentTimeMillis() - start);
	}
	
}
