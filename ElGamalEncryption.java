package cryptotoolbox;
import java.math.BigInteger;
import java.util.Random;
import cryptotoolbox.MathUtil;
import cryptotoolbox.Pair;
public class ElGamalEncryption {
	private BigInteger p;
	private BigInteger q;
	private BigInteger g;
	private BigInteger s;
	private BigInteger h;
	private int qBit;
	private int kBit;
	private MathUtil util=new MathUtil();
	
	public ElGamalEncryption(int securityLevel){
		switch(securityLevel){
			case 1:qBit=160;
				   kBit=864;
				   break;
			case 2:qBit=224;
				   kBit=1824;
				   break;
			case 3:qBit=256;
				   kBit=2816;
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
	public void generatePrivateKey(){
		Random rnd= new Random();
		do{
			s=new BigInteger(qBit,rnd);
		}while(s.compareTo(q.subtract(new BigInteger("2")))>0);
	}
	public void generatePublicKey(){
	
		h=util.expmod_BR2L(g, s, p);
	}
	public Pair<BigInteger,BigInteger> encrypt(BigInteger g,BigInteger h,BigInteger p,BigInteger m){
		BigInteger k;
		Random rnd= new Random();
		do{
			k=new BigInteger(qBit,rnd);
		}while(k.compareTo(q.subtract(new BigInteger("1")))>=0);
	
		BigInteger r=util.expmod_BR2L(g, k, p);
		BigInteger t=util.expmod_BR2L(h, k, p).multiply(m).mod(p);
		return new Pair<BigInteger, BigInteger>(r,t);
	}
	public BigInteger decrypt(BigInteger r,BigInteger t,BigInteger s,BigInteger p){
		
		BigInteger message=(t.multiply(util.expmod_BR2L(util.modinv(r, p),s,p))).mod(p);
		return message;
	}
	public BigInteger getG(){
		return g;
	}
	public BigInteger getP(){
		return p;
	}
	public BigInteger getH(){
		return h;
	}
	public BigInteger getQ() {
		return q;
	}
	public BigInteger getS(){
		return s;
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
	public void setS(BigInteger s){
		this.s=s;
	}
}
