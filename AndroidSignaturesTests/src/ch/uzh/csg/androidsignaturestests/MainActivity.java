package ch.uzh.csg.androidsignaturestests;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;

import android.app.Activity;
import android.app.Fragment;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

public class MainActivity extends Activity {
	
	private static final String TAG = "MainActivity";
	private static final String PLAIN_TEXT = "lorem ipsum blablabla";
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		if (savedInstanceState == null) {
			getFragmentManager().beginTransaction().add(R.id.container, new PlaceholderFragment()).commit();
		}
		
		measureCreate1024Keys();
		measureCreate2048Keys();
		
		measureSHA1withRSA1024();
		measureSHA1withRSA2048();
		measureSHA256withRSA1024();
		measureSHA256withRSA2048();
	}
	
	private static void measureCreate1024Keys() {
		Log.d(TAG, "start benchmark - RSA-1024");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(create1024Keys());
			} catch (NoSuchAlgorithmException e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - RSA-1024");
	}
	
	private static long create1024Keys() throws NoSuchAlgorithmException {
		long start = System.currentTimeMillis();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.generateKeyPair();
		return (start - System.currentTimeMillis());
	}
	
	private static void measureCreate2048Keys() {
		Log.d(TAG, "start benchmark - RSA-2048");
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(create2048Keys());
			} catch (NoSuchAlgorithmException e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - RSA-2048");
	}
	
	private static long create2048Keys() throws NoSuchAlgorithmException {
		long start = System.currentTimeMillis();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		keyGen.generateKeyPair();		
		return (start - System.currentTimeMillis());
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
		
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		byte[] digest2 = digest.digest(PLAIN_TEXT.getBytes("UTF-8"));
		
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKey);
		rsa.update(digest2);
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
				
				builder.append(SHA1withRSA2048(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA1withRSA2048");
	}
	
	private static long SHA1withRSA2048(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		long start = System.currentTimeMillis();
		
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		byte[] digest2 = digest.digest(PLAIN_TEXT.getBytes("UTF-8"));
		
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKey);
		rsa.update(digest2);
		rsa.sign();
		
		return (start - System.currentTimeMillis());
	}
	
	private static void measureSHA256withRSA1024() {
		Log.d(TAG, "start benchmark - SHA256withRSA1024");
		
		PrivateKey privateKey = generateNewKey(1024);
		
		StringBuilder builder = new StringBuilder();
		
		for (int i=0; i<10; i++) {
			try {
				if (i > 0)
					builder.append(", ");
				
				builder.append(SHA256withRSA1024(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withRSA1024");
	}
	
	private static long SHA256withRSA1024(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		long start = System.currentTimeMillis();
		
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] digest2 = digest.digest(PLAIN_TEXT.getBytes("UTF-8"));
		
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(privateKey);
		rsa.update(digest2);
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
				
				builder.append(SHA256withRSA2048(privateKey));
			} catch (Exception e) {
				Log.e(TAG, "error", e);
				break;
			}
		}
		
		Log.d(TAG, builder.toString());
		Log.d(TAG, "finished benchmark - SHA256withRSA1024");
	}
	
	private static long SHA256withRSA2048(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		long start = System.currentTimeMillis();
		
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] digest2 = digest.digest(PLAIN_TEXT.getBytes("UTF-8"));
		
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(privateKey);
		rsa.update(digest2);
		rsa.sign();
		
		return (start - System.currentTimeMillis());
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

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	/**
	 * A placeholder fragment containing a simple view.
	 */
	public static class PlaceholderFragment extends Fragment {

		public PlaceholderFragment() {
		}

		@Override
		public View onCreateView(LayoutInflater inflater, ViewGroup container,
				Bundle savedInstanceState) {
			View rootView = inflater.inflate(R.layout.fragment_main, container,
					false);
			return rootView;
		}
	}

}
