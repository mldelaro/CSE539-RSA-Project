import java.math.BigInteger;
import java.util.Random;

public class RsaServer {
	
	private static final int m_PublicKeyLength = 0; //TODO: Determine key length
	
	private Random m_PRG;
	private BigInteger m_PrivateKey;
	private BigInteger m_RandomPrime1;
	private BigInteger m_RandomPrime2;
	private BigInteger m_PublicProduct;
	private BigInteger m_PublicExponent;
	private byte[] m_PublicKey;
		
	public RsaServer() {
		m_PRG = new Random(1);
	}
	
	public void generatePublicKey() {
		//Generate two random primes
		BigInteger p1 = new BigInteger(50, 99, m_PRG);
		BigInteger p1minus1 = p1.subtract(BigInteger.ONE);
		this.setRandomPrime1(p1);
		
		BigInteger p2 = new BigInteger(50, 99, m_PRG);
		BigInteger p2minus1 = p2.subtract(BigInteger.ONE);
		this.setRandomPrime2(p2);
		
		//Get the product of the random primes
		BigInteger n = p1.multiply(p2);
		this.setPublicProduct(n);

		//Calculate Phi of product
		BigInteger phiOfN = p1minus1.multiply(p2minus1);
		
		//Generate public exponent
		BigInteger publicExponent = BigInteger.ZERO;
		publicExponent = publicExponent.add(BigInteger.ONE);
		publicExponent = publicExponent.add(BigInteger.ONE);
		publicExponent = publicExponent.add(BigInteger.ONE);		
		
		/*TODO: Expand on Euclid's extended algorithm ?
		 * Find a suitable public 'e' (e = 3 is sufficient for now) */
		while(publicExponent.gcd(phiOfN).compareTo(BigInteger.ONE) != 0 ||
				publicExponent.compareTo(BigInteger.ONE) == 0) {
			publicExponent = new BigInteger(10, m_PRG);
		}
		this.setPublicExponent(publicExponent);
		
		//Calculate private key
		BigInteger two = BigInteger.valueOf(2);
		BigInteger one = BigInteger.valueOf(1);
		BigInteger privateKey = two.multiply(phiOfN);
		privateKey = privateKey.add(one);
		privateKey = privateKey.divide(publicExponent);
		this.setPrivateKey(privateKey);
		
		System.out.println("Alice calculates Shares: ");
		System.out.println("n = " + n.toString());
		System.out.println("e = " + publicExponent.toString());
	}
	
	public void receiveCiphertext(byte[] bytesCiphertext) {
		BigInteger biCiphertext = new BigInteger(1, bytesCiphertext);
		String testval = new String(biCiphertext.toByteArray());
		System.out.println("Server received: " + testval);
		
		System.out.println("Alice receives c and decrypts with private key");
		BigInteger m2 = biCiphertext.modPow(this.getPrivateKey(), this.getPublicProduct());
		
		String testval2 = new String(m2.toByteArray());
		System.out.println("Decrypted Message: " + testval2);		

	}
	
	public void displayMessage() {
		
	}
	
	private BigInteger getPrivateKey() {
		return m_PrivateKey;
	}

	private void setPrivateKey(BigInteger m_PrivateKey) {
		this.m_PrivateKey = m_PrivateKey;
	}

	private BigInteger getRandomPrime1() {
		return m_RandomPrime1;
	}

	private void setRandomPrime1(BigInteger m_RandomPrime1) {
		this.m_RandomPrime1 = m_RandomPrime1;
	}

	private BigInteger getRandomPrime2() {
		return m_RandomPrime2;
	}

	private void setRandomPrime2(BigInteger m_RandomPrime2) {
		this.m_RandomPrime2 = m_RandomPrime2;
	}

	public BigInteger getPublicProduct() {
		return m_PublicProduct;
	}

	private void setPublicProduct(BigInteger m_PublicProduct) {
		this.m_PublicProduct = m_PublicProduct;
	}

	public BigInteger getPublicExponent() {
		return m_PublicExponent;
	}

	private void setPublicExponent(BigInteger m_PublicExponent) {
		this.m_PublicExponent = m_PublicExponent;
	}

	private byte[] getPublicKey() {
		return m_PublicKey;
	}

	private void setPublicKey(byte[] m_PublicKey) {
		this.m_PublicKey = m_PublicKey;
	}
}