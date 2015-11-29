package encrypt.rsa;
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
	private String m_lastMessage;
		
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
		 * Find a suitable public 'e' (e = 3 is sufficient for now) 
		 * Choose d and e S.T d*e = 1 mod phi(n)*/
		while(publicExponent.gcd(phiOfN).compareTo(BigInteger.ONE) != 0 ||
				publicExponent.compareTo(BigInteger.ONE) == 0) {
			publicExponent = new BigInteger(10, m_PRG);
		}
		System.out.println("**DEBUG** gcd - " + publicExponent.toString() + " : " + publicExponent.gcd(phiOfN));
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
		BigInteger biMessage = biCiphertext.modPow(this.getPrivateKey(), this.getPublicProduct());
		
		String strMessage = new String(biMessage.toByteArray());
		System.out.println("Decrypted Message: " + strMessage);
		this.setLastDecryptedMessage(strMessage);
	}
	
	public BigInteger PUBLISH_PublicProduct() {
		return this.m_PublicProduct;
	}
	
	public BigInteger PUBLISH_PublicExponent() {
		return this.m_PublicExponent;
	}
	
	public String PUBLISH_LastDecryptedMessage() {
		return this.m_lastMessage;
	}
	
	private BigInteger getPrivateKey() {
		return m_PrivateKey;
	}

	private void setPrivateKey(BigInteger privateKey) {
		this.m_PrivateKey = privateKey;
	}

	private BigInteger getRandomPrime1() {
		return m_RandomPrime1;
	}

	private void setRandomPrime1(BigInteger randomPrime1) {
		this.m_RandomPrime1 = randomPrime1;
	}

	private BigInteger getRandomPrime2() {
		return m_RandomPrime2;
	}

	private void setRandomPrime2(BigInteger randomPrime2) {
		this.m_RandomPrime2 = randomPrime2;
	}

	private BigInteger getPublicProduct() {
		return m_PublicProduct;
	}

	private void setPublicProduct(BigInteger publicProduct) {
		this.m_PublicProduct = publicProduct;
	}

	private BigInteger getPublicExponent() {
		return m_PublicExponent;
	}

	private void setPublicExponent(BigInteger publicExponent) {
		this.m_PublicExponent = publicExponent;
	}

	private byte[] getPublicKey() {
		return m_PublicKey;
	}

	private void setPublicKey(byte[] publicKey) {
		this.m_PublicKey = publicKey;
	}
	
	private String getLastDecryptedMessage() {
		return this.m_lastMessage;
	}
	
	private void setLastDecryptedMessage(String lastMessage) {
		this.m_lastMessage = lastMessage;
	}
}