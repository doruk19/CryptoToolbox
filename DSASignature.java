package cryptotoolbox;

import java.math.BigInteger;
import java.util.Random;
import cryptotoolbox.Hasher;
import cryptotoolbox.MathUtil;
import cryptotoolbox.Pair;

public class DSASignature {
	private BigInteger p;
	private BigInteger q;
	private BigInteger g;
	private BigInteger a;
	private BigInteger beta;
	private int qBit;
	private int kBit;
	private MathUtil util=new MathUtil();
	private String hashAlgo;
	
	public DSASignature(int securityLevel){
		switch(securityLevel){
			case 1:qBit=160;
				   kBit=864;
				   hashAlgo="SHA-256";
				   break;
			case 2:qBit=224;
				   kBit=1824;
				   hashAlgo="SHA-384";
				   break;
			case 3:qBit=256;
				   kBit=2816;
				   hashAlgo="SHA-512";
				   break;
			default:
				System.out.println("Unknown Security Level");
				break;
		}
	}
	public void generateParameters(){
		Random rnd= new Random();
		BigInteger k;
		do{
			q=new BigInteger(qBit,100,rnd);
		}while(!util.MillerRabinTest(q, 100));
		
		do{
			k=new BigInteger(kBit,rnd);
			p=(k.multiply(q)).add(BigInteger.ONE);
		}while(!p.isProbablePrime(100));
		do{
			BigInteger a=new BigInteger(qBit+kBit,rnd);
			g=util.expmod_BR2L(a, (p.subtract(BigInteger.ONE)).divide(q), p);
		}while (g.equals(BigInteger.ONE));
	}
	public void generatePublicKey(){
		
		beta=util.expmod_BR2L(g, a, p);
	}	
	public void generatePrivateKey(){
		Random rnd= new Random();
		do{
			a=new BigInteger(qBit,rnd);
		}while(a.compareTo(q.subtract(new BigInteger("2")))>0);
	}
	public Pair<BigInteger,BigInteger> sign(BigInteger message){
		BigInteger k;
		Random rnd= new Random();
		do{
			k=new BigInteger(qBit,rnd);
		}while(a.compareTo(q)>=0);
		BigInteger hash=new BigInteger((new Hasher()).getHash(message.toByteArray(),hashAlgo));
		BigInteger r=util.expmod_BR2L(g, k, p).mod(q);
		BigInteger s=(util.modinv(k, q).multiply(hash.add(a.multiply(r)))).mod(q);
		return new Pair<BigInteger,BigInteger>(r,s);
	}
	public boolean verify(BigInteger r,BigInteger s,BigInteger message,BigInteger p,BigInteger q,BigInteger g,BigInteger beta,String hashAlgo){
		
		BigInteger hash=new BigInteger((new Hasher()).getHash(message.toByteArray(),hashAlgo));
		BigInteger u1=(util.modinv(s, q).multiply(hash)).mod(q);
		BigInteger u2=(util.modinv(s, q).multiply(r)).mod(q);
		BigInteger v=((util.expmod_BR2L(g, u1, p)).multiply(util.expmod_BR2L(beta, u2, p))).mod(p).mod(q);
	
		return v.equals(r);
	}
	public BigInteger getG(){
		return g;
	}
	public BigInteger getP(){
		return p;
	}
	public BigInteger getBeta(){
		return beta;
	}
	public BigInteger getQ(){
		return q;
	}
	public BigInteger getA(){
		return a;
	}
	public String getHashAlgo(){
		return hashAlgo;
	}
	public void setG(BigInteger g){
		this.g=g;
	}
	public void setP(BigInteger p){
		this.p=p;
	}
	public void setQ(BigInteger q){
		this.q=q;
	}
	public void setA(BigInteger a){
		this.a=a;
	}
	public void setHashAlgo(String hashAlgo){
		this.hashAlgo=hashAlgo;
	}
	
}
