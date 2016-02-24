package cryptotoolbox;

import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class TDES {
	
	public byte[] encrypt(byte[] message,byte[] keyBytes,byte[] ivBlock) throws Exception {

    	final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
    	final IvParameterSpec iv = new IvParameterSpec(ivBlock);
    	final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    	cipher.init(Cipher.ENCRYPT_MODE, key, iv);

    	final byte[] cipherText = cipher.doFinal(message);
    	
    	return cipherText;
    }

    public byte[] decrypt(byte[] message,byte[] keyBytes,byte[] ivBlock) throws Exception {
    

    	final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
    	final IvParameterSpec iv = new IvParameterSpec(ivBlock);
    	final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
    	decipher.init(Cipher.DECRYPT_MODE, key, iv);
     	return decipher.doFinal(message);
     	
    }
}
	

