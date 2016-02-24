package cryptotoolbox;

import java.math.BigInteger;
import java.util.Random;

public class RSAPSS {

	private int bitsize;
	private BigInteger n;
	private BigInteger p;
	private BigInteger q;
	private BigInteger e;
	private BigInteger d;
	private BigInteger phi;
	private String hashAlgo;
	private MathUtil util=new MathUtil();
	private Hasher hsh=new Hasher();
	private int lRunCount;
	private String padding1="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	private String padding2="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
	private int hSize;
	public RSAPSS(int securityLevel){
		
		switch(securityLevel){	
			case 1:
				bitsize=1024;
				hashAlgo="SHA-256";
				lRunCount=3;
				hSize=256;
				break;
			case 2:
				bitsize=2048;
				hashAlgo="SHA-384";
				lRunCount=5;
				hSize=384;
				break;
			case 3:
				bitsize=3072;
				hashAlgo="SHA-512";
				lRunCount=5;
				hSize=512;
				break;
			default:
				System.out.println("Unknown Security Level");
				break;
		}
	}
	public void generatePublicKeys(){
		
		Random rnd = new Random();
		do{
			p=new BigInteger(bitsize/2,100,rnd);
		}while(!util.MillerRabinTest(p, 100));
		do{
			q=new BigInteger(bitsize/2,100,rnd);
		}while(!util.MillerRabinTest(p, 100)||p.equals(q));
		
		n=p.multiply(q);
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		do{
			e=new BigInteger(bitsize,rnd);
		}while(!util.gcdEA(e, phi).equals(BigInteger.ONE));
		
	}
	public void generatePrivateKey(){
		phi=(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
		d=util.modinv(e, phi);
	}
	private BigInteger RSAEP(BigInteger n,BigInteger e,BigInteger m){
		return util.expmod_BR2L(m, e, n);
	}
	private BigInteger RSADP(BigInteger n,BigInteger d,BigInteger c){
		return util.expmod_BR2L(c, d, n);
	}
	private BigInteger RSAVP(BigInteger n,BigInteger e,BigInteger s){
	
		return util.expmod_BR2L(s, e, n);
	}
	private BigInteger RSASP(BigInteger n,BigInteger d,BigInteger m){
		return util.expmod_BR2L(m, d, n);
	}
	public BigInteger sign(BigInteger message){
		String mHash=util.HexToString(Hasher.getHash(message.toByteArray(),hashAlgo));
		Random rnd = new Random();
		BigInteger salt=new BigInteger(128,rnd);
		String M = padding1+mHash+salt.toString(16) ;
		String DB= padding2+salt.toString(16);
		String H= util.HexToString(Hasher.getHash(util.StringToHex(M), hashAlgo));
		BigInteger lH=L(new BigInteger(H,16));
		BigInteger maskedDB = lH.xor(new BigInteger(DB,16));
		String signature=maskedDB.toString(16)+H;
		return RSASP(n,d,new BigInteger(signature,16));
	}
	public boolean verify(BigInteger message,BigInteger signature,BigInteger n,BigInteger e){
		
		BigInteger sign = RSAVP(n,e,signature);
		BigInteger seperator = (new BigInteger("2")).pow(hSize);
		BigInteger maskedDB=sign.divide(seperator);
		BigInteger H=sign.mod(seperator);
		BigInteger lH=L(H);
		BigInteger DB = maskedDB.xor(lH);
		BigInteger salt=DB.mod(new BigInteger("2").pow(128));
		String mHash=util.HexToString(Hasher.getHash(message.toByteArray(),hashAlgo));
		String M = padding1+mHash+salt.toString(16) ;
		String MH= util.HexToString(Hasher.getHash(util.StringToHex(M), hashAlgo));
		
		return MH.equals(H.toString(16));
		
	}
	private BigInteger L(BigInteger r){
		
		String lR="";
		for(int i=1;i<=lRunCount;i++)
		{
		lR+=util.HexToString(hsh.getHash(((r.multiply(new BigInteger("4"))).add(new BigInteger(""+i))).toByteArray(),"SHA-256"));
		}
		return new BigInteger(lR,16);
	}
	public BigInteger getP(){
		return p;
	}
	public BigInteger getQ(){
		return q;
	}
	public BigInteger getE(){
		return e;
	}
	public BigInteger getN(){
		return n;
	}
	public BigInteger getD(){
		return d;
	}
	public void setP(BigInteger p){
		this.p=p;
	}
	public void setQ(BigInteger q){
		this.q=q;
	}
	public void setE(BigInteger e){
		this.e=e;
	}
	public void setN(){
		n=p.multiply(q);
	}
}
