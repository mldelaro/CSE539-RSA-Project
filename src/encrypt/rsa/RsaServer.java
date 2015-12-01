package encrypt.rsa;
import java.math.BigInteger;
import java.util.Random;

public class RsaServer {
	
	private static final int m_PublicKeyLength = 0; //TODO: Determine key length
	
	private Random m_PRG;
	private LargeInt m_PrivateKey;
	private LargeInt m_RandomPrime1;
	private LargeInt m_RandomPrime2;
	private LargeInt m_PublicProduct;
	private LargeInt m_PublicExponent;
	private byte[] m_PublicKey;
	private String m_LastMessage;
		
	public RsaServer() {
		m_PRG = new Random(1);
	}
	
	public void generatePublicKey() {
		//Generate two random primes
		LargeInt p1 = new LargeInt(new BigInteger(512, 99, m_PRG).toByteArray());
		LargeInt p1minus1 = p1.minus(LargeInt.ONE);
		this.setRandomPrime1(p1);
		
		LargeInt p2 = new LargeInt(new BigInteger(512, 99, m_PRG).toByteArray());
		LargeInt p2minus1 = p2.minus(LargeInt.ONE);
		this.setRandomPrime2(p2);
		
		//Get the product of the random primes
		LargeInt n = p1.multiply(p2);
		this.setPublicProduct(n);

		//Calculate Phi of product
		LargeInt phiOfN = p1minus1.multiply(p2minus1);
		
		//Generate public exponent
		//LargeInt publicExponent = LargeInt.ZERO;
		//publicExponent = publicExponent.plus(LargeInt.ONE);
		//publicExponent = publicExponent.plus(LargeInt.ONE);
		//publicExponent = publicExponent.plus(LargeInt.ONE);
		LargeInt publicExponent = new LargeInt(3);
		
		/*TODO: Expand on Euclid's extended algorithm ?
		 * Find a suitable public 'e' (e = 3 is sufficient for now) 
		 * Choose d and e S.T d*e = 1 mod phi(n)*/
		//System.out.println("**DEBUG** asdfsdfsdf");

		while(new BigInteger(publicExponent.toByteArray()).gcd(new BigInteger(phiOfN.toByteArray())).compareTo(BigInteger.ONE) != 0 ||
				publicExponent.compareTo(LargeInt.ONE) == 0) {
			System.out.println("**DEBUG** asdfsdfsdf");
			publicExponent = new LargeInt(new BigInteger(10, m_PRG).toByteArray());
		}
		System.out.println("**DEBUG** gcd - " + new BigInteger(publicExponent.toByteArray()).toString() + " : " + new BigInteger(publicExponent.toByteArray()).gcd(new BigInteger(phiOfN.toByteArray())));
		this.setPublicExponent(publicExponent);
		
		//Calculate private key
		LargeInt two = new LargeInt(2);
		LargeInt one = new LargeInt(1);
		LargeInt privateKey = two.multiply(phiOfN);
		privateKey = privateKey.plus(one);
		privateKey = privateKey.divide(publicExponent);
		this.setPrivateKey(privateKey);
		
		System.out.println("Alice calculates Shares: ");
		System.out.println("n = " + new BigInteger(n.toByteArray()).toString());
		System.out.println("e = " + new BigInteger(publicExponent.toByteArray()).toString());
	}
	
	public void receiveCiphertext(byte[] bytesCiphertext) {
		LargeInt biCiphertext = new LargeInt(bytesCiphertext);
		String testval = new String(biCiphertext.toByteArray());
		System.out.println("Server received: " + testval);
		
		System.out.println("Alice receives c and decrypts with private key");
		LargeInt biMessage = new LargeInt(new BigInteger(biCiphertext.toByteArray()).modPow(new BigInteger(this.getPrivateKey().toByteArray()), new BigInteger(this.getPublicProduct().toByteArray())).toByteArray());
		
		String strMessage = new String(biMessage.toByteArray());
		System.out.println("Decrypted Message: " + strMessage);
		this.setLastDecryptedMessage(strMessage);
	}
	
	public LargeInt PUBLISH_PublicProduct() {
		return this.m_PublicProduct;
	}
	
	public LargeInt PUBLISH_PublicExponent() {
		return this.m_PublicExponent;
	}
	
	public String PUBLISH_LastDecryptedMessage() {
		return this.m_LastMessage;
	}
	
	private LargeInt getPrivateKey() {
		return m_PrivateKey;
	}

	private void setPrivateKey(LargeInt privateKey) {
		this.m_PrivateKey = privateKey;
	}

	private LargeInt getRandomPrime1() {
		return m_RandomPrime1;
	}

	private void setRandomPrime1(LargeInt randomPrime1) {
		this.m_RandomPrime1 = randomPrime1;
	}

	private LargeInt getRandomPrime2() {
		return m_RandomPrime2;
	}

	private void setRandomPrime2(LargeInt randomPrime2) {
		this.m_RandomPrime2 = randomPrime2;
	}

	private LargeInt getPublicProduct() {
		return m_PublicProduct;
	}

	private void setPublicProduct(LargeInt publicProduct) {
		this.m_PublicProduct = publicProduct;
	}

	private LargeInt getPublicExponent() {
		return m_PublicExponent;
	}

	private void setPublicExponent(LargeInt publicExponent) {
		this.m_PublicExponent = publicExponent;
	}

	private byte[] getPublicKey() {
		return m_PublicKey;
	}

	private void setPublicKey(byte[] publicKey) {
		this.m_PublicKey = publicKey;
	}
	
	private String getLastDecryptedMessage() {
		return this.m_LastMessage;
	}
	
	private void setLastDecryptedMessage(String lastMessage) {
		this.m_LastMessage = lastMessage;
	}
}