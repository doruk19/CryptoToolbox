package cryptotoolbox;

import cryptotoolbox.MathUtil;
import java.math.BigInteger;
import java.util.Random;


public class RSAOAEP {
	private int bitsize;
	private BigInteger n;
	private BigInteger p;
	private BigInteger q;
	private BigInteger e;
	private BigInteger d;
	private BigInteger phi;
	private MathUtil util=new MathUtil();
	private Hasher hsh=new Hasher();
	private int sLevel;
	public RSAOAEP(int securityLevel){
		
		sLevel=securityLevel;
		switch(securityLevel){	
			case 1:
				bitsize=1024;
				break;
			case 2:
				bitsize=2048;
				break;
			case 3:
				bitsize=3072;
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
	public BigInteger encrypt(BigInteger m, BigInteger n, BigInteger e){
		int mBit=m.bitLength();
		if(mBit>bitsize-(256+128+1)){
			System.out.println("Error:Message is too big");
			return null;
		}
		else{
			Random rnd = new Random();
			int rSize = rnd.nextInt(129)+128;
			BigInteger r=new BigInteger(rSize,rnd);
			BigInteger m0=m.multiply((new BigInteger("2")).pow(128));
			BigInteger gR=G(r);
			BigInteger X=m0.xor(gR);
			BigInteger Y=r.xor(new BigInteger(hsh.getHash(X.toByteArray(), "SHA-256")));
			String encryption = X.toString(16)+Y.toString(16);
			
			return RSAEP(n,e,new BigInteger(encryption,16));
		}
	}
	public BigInteger decrypt(BigInteger c,BigInteger d,BigInteger n){
		BigInteger decrypted=RSADP(n,d,c);
		final BigInteger seperator= new BigInteger("2").pow(256);
		BigInteger X=decrypted.divide(seperator);
		BigInteger Y=decrypted.mod(seperator);
		BigInteger r=Y.xor(new BigInteger(hsh.getHash(X.toByteArray(), "SHA-256")));
		BigInteger gR=G(r);
		BigInteger m0=X.xor(gR);
		
		return m0.divide((new BigInteger("2")).pow(128));
	}
	private BigInteger G(BigInteger r){
		
		String gR="";
		for(int i=1;i<=(sLevel*4-1);i++)
		{
		gR+=util.HexToString(hsh.getHash(((r.multiply(new BigInteger("4"))).add(new BigInteger(""+i))).toByteArray(),"SHA-256"));
		}
		return new BigInteger(gR,16);
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
