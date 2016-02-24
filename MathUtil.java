package cryptotoolbox;
import java.math.BigInteger;
import java.util.Random;

public class MathUtil {

	private static final BigInteger ZERO = BigInteger.ZERO;
	private static final BigInteger ONE = BigInteger.ONE;
	private static final BigInteger TWO = new BigInteger("2");
	private static final BigInteger THREE = new BigInteger("3");

	
	public static boolean MillerRabinTest(BigInteger n,int k)
	{
		if(n.mod(TWO)==ZERO)
			return false;
		
		if (n.compareTo(THREE) < 0)
			return true;
		int s = 0;
		BigInteger d = n.subtract(ONE);
		while (d.mod(TWO).equals(ZERO)) {
			s++;
			d = d.divide(TWO);
		}
		for (int i = 0; i < k; i++) {
			BigInteger a = uniformRandom(TWO, n.subtract(ONE));
			BigInteger x = a.modPow(d, n);
			if (x.equals(ONE) || x.equals(n.subtract(ONE)))
				continue;
			int r = 1;
			for (; r < s; r++) {
				x = x.modPow(TWO, n);
				if (x.equals(ONE))
					return false;
				if (x.equals(n.subtract(ONE)))
					break;
			}
			if (r == s) // None of the steps made x equal n-1.
				return false;
		}
		return true;
	}
	private static BigInteger uniformRandom(BigInteger bottom, BigInteger top) {
		Random rnd = new Random();
		BigInteger res;
		do {
			res = new BigInteger(top.bitLength(), rnd);
		} while (res.compareTo(bottom) < 0 || res.compareTo(top) > 0);
		return res;
	}
	public static BigInteger gcdEA(BigInteger a,BigInteger b){
		while(b!=ZERO){
			BigInteger temp=a;
			a=b;
			b=temp.mod(b);
		}
		return a;
	}
	public static BigInteger expmod_BR2L(BigInteger number,BigInteger exponent,BigInteger modulo){
		BigInteger x=ONE;
		BigInteger y=number;
		while(exponent.compareTo(ZERO)>0){
			if(exponent.and(ONE).compareTo(ONE)==0){
				
				x=(x.multiply(y)).mod(modulo);
			
			}
			y=(y.multiply(y)).mod(modulo);
			exponent=exponent.shiftRight(1);
		}
		return x.mod(modulo);
	}	
	public static BigInteger modinv(BigInteger number,BigInteger modulo){
		return number.modInverse(modulo);
	}
public static byte[] StringToHex(String input){
		
		int len = input.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(input.charAt(i), 16) << 4)
	                             + Character.digit(input.charAt(i+1), 16));
	    }
	    return data;
		
	}
	public static String HexToString(byte[] arr){
		final char[] hexArray = "0123456789abcdef".toCharArray();
		char[] hexChars = new char[arr.length * 2];
	    for ( int j = 0; j < arr.length; j++ ) {
	        int v = arr[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}

}

