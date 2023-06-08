package rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class CipherRSA {
	static Cipher cipher;
	static PrivateKey prikey;
	static PublicKey pubkey;
	static {
		try {
			cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //
			//공개키(RSA) 암호화에 사용될 키 생성
			KeyPairGenerator key = KeyPairGenerator.getInstance("RSA");
			KeyPair keyPair = key.genKeyPair();; //키의 쌍인 객체 저장
			prikey = keyPair.getPrivate(); //개인키
			pubkey = keyPair.getPublic(); //공개키
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	public static String encrypt(String plain1) { //암호화
		//plain1 : 평문
		byte[] cipherMsg = new byte[1024];
		try {
			cipher.init(Cipher.ENCRYPT_MODE,prikey); //암호화모드, 개인키
			cipherMsg = cipher.doFinal(plain1.getBytes()); //암호화
		} catch (Exception e) {
			e.printStackTrace();
		}
		return byteToHex(cipherMsg); //16진수 문자열로 리턴
	}
	private static String byteToHex(byte[] cipherMsg) {
		if(cipherMsg == null) return null;
		String str = "";
		for(byte b : cipherMsg) {
			str += String.format("%02X", b);
		}
		return str;
	}

	public static String decrypt(String cipher1) {
		//cipher1 : 암호문. 16진수표현된 문자열
		byte[] plainMsg = new byte[1024];
		try {
			cipher.init(Cipher.DECRYPT_MODE, pubkey);
			plainMsg = cipher.doFinal(hexToByte(cipher1.trim()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(plainMsg).trim();
	}
	// 16진수표현의 문자열 => byte[] 
	private static byte[] hexToByte(String str) {
		if(str == null || str.length() < 2) return null; 
		int len = str.length() / 2; 
		byte[] buf = new byte[len];
		for(int i = 0; i< buf.length; i++) {
			buf[i] = (byte) Integer.parseInt(str.substring(i * 2, i * 2 + 2), 16);
		}
		return buf;
	}

}
