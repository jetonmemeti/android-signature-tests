package ch.uzh.csg.androidsignaturestests;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
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
	
	private static final String PLAIN_TEXT = "lorem ipsum blablabla";
	
	private static PrivateKey key1024;
	private static PrivateKey key2048;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);

		if (savedInstanceState == null) {
			getFragmentManager().beginTransaction().add(R.id.container, new PlaceholderFragment()).commit();
		}
		
		KeyPairGenerator keyGen = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			Log.e("MainActivity", "error", e);
			System.exit(0);
		}
		
		key1024 = keyGen.generateKeyPair().getPrivate();
		
		keyGen.initialize(2048);
		key2048 = keyGen.generateKeyPair().getPrivate();
		
		measureCreate1024Keys();
		measureCreate2048Keys();
		
		measureRunTime1();
		measureRunTime2();
		measureRunTime3();
		measureRunTime4();
	}
	
	private static void measureCreate1024Keys() {
		long start = System.currentTimeMillis();
		for (int i=0; i<10; i++) {
			try {
				create1024Keys();
			} catch (NoSuchAlgorithmException e) {
				Log.e("MainActivity", "error", e);
				break;
			}
		}
		long end = System.currentTimeMillis();
		Log.d("MainActivity", "SHA1-RSA1024, total duration in ms: "+(end-start));
	}
	
	private static void create1024Keys() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		KeyPair keyPair = keyGen.generateKeyPair();
	}
	
	private static void measureCreate2048Keys() {
		long start = System.currentTimeMillis();
		for (int i=0; i<10; i++) {
			try {
				create2048Keys();
			} catch (NoSuchAlgorithmException e) {
				Log.e("MainActivity", "error", e);
				break;
			}
		}
		long end = System.currentTimeMillis();
		Log.d("MainActivity", "SHA1-RSA1024, total duration in ms: "+(end-start));
	}

	private static void create2048Keys() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair keyPair = keyGen.generateKeyPair();		
	}

	private static void measureRunTime1() {
		long start = System.currentTimeMillis();
		for (int i=0; i<10; i++) {
			try {
				SHA1withRSA(key1024);
			} catch (Exception e) {
				Log.e("MainActivity", "error", e);
				break;
			}
		}
		long end = System.currentTimeMillis();
		Log.d("MainActivity", "SHA1-RSA1024, total duration in ms: "+(end-start));
	}
	
	private static void measureRunTime2() {
		long start = System.currentTimeMillis();
		for (int i=0; i<10; i++) {
			try {
				SHA1withRSA2048(key2048);
			} catch (Exception e) {
				Log.e("MainActivity", "error", e);
				break;
			}
		}
		long end = System.currentTimeMillis();
		Log.e("MainActivity", "SHA1-RSA2048, total duration in ms: "+(end-start));
	}
	
	private static void measureRunTime3() {
		long start = System.currentTimeMillis();
		for (int i=0; i<10; i++) {
			try {
				SHA256withRSA(key1024);
			} catch (Exception e) {
				Log.e("MainActivity", "error", e);
				break;
			}
		}
		long end = System.currentTimeMillis();
		Log.e("MainActivity", "SHA256-RSA1024, total duration in ms: "+(end-start));
	}
	
	private static void measureRunTime4() {
		long start = System.currentTimeMillis();
		for (int i=0; i<10; i++) {
			try {
				SHA256withRSA2048(key2048);
			} catch (Exception e) {
				Log.e("MainActivity", "error", e);
				break;
			}
		}
		long end = System.currentTimeMillis();
		Log.e("MainActivity", "SHA256-RSA2048, total duration in ms: "+(end-start));
	}
	
	private static void SHA1withRSA(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		byte[] digest2 = digest.digest(PLAIN_TEXT.getBytes("UTF-8"));
		System.out.println("size of digest: "+digest2.length);
		
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKey);
		rsa.update(digest2);
		byte[] sign = rsa.sign();
		System.out.println("size of the signature: "+sign.length);
	}
	
	private static void SHA256withRSA(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] digest2 = digest.digest(PLAIN_TEXT.getBytes("UTF-8"));
		System.out.println("size of digest: "+digest2.length);
		
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(privateKey);
		rsa.update(digest2);
		byte[] sign = rsa.sign();
		System.out.println("size of the signature: "+sign.length);
	}
	
	private static void SHA1withRSA2048(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		MessageDigest digest = MessageDigest.getInstance("SHA-1");
		byte[] digest2 = digest.digest(PLAIN_TEXT.getBytes("UTF-8"));
		System.out.println("size of digest: "+digest2.length);
		
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privateKey);
		rsa.update(digest2);
		byte[] sign = rsa.sign();
		System.out.println("size of the signature: "+sign.length);
	}
	
	private static void SHA256withRSA2048(PrivateKey privateKey) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException, SignatureException{
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] digest2 = digest.digest(PLAIN_TEXT.getBytes("UTF-8"));
		System.out.println("size of digest: "+digest2.length);
		
		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(privateKey);
		rsa.update(digest2);
		byte[] sign = rsa.sign();
		System.out.println("size of the signature: "+sign.length);
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
