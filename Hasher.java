package cryptotoolbox;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hasher {
	
	public static byte[] getHash(byte[] input, String algorithm) {
		try {
				MessageDigest md = MessageDigest.getInstance(algorithm);
				md.update(input);
				byte[] digest = md.digest();
			
				return digest;
		} catch(NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}
}
