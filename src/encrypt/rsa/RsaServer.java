/*
 * @FileName: RsaServer.java
 * 
 * @Date: November 2015
 * @Author: Michael Bradley, Matthew de la Rosa
 * 
 * @Description: RsaServer is responsible for generating the public key and private key, and
 * 		decrypting ciphertexts received. In a secure transaction, the RsaServer
 * 		should also unpad their message properly in order to prevent any malleable attacks 
 */

package encrypt.rsa;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import encrypt.rsa.util.RsaUtility;

public class RsaServer {
	
	private Random m_PRG; // Used to generate random values
	
	private BigInteger m_PrivateKey;	// d - used to decrypt messages
	private BigInteger m_RandomPrime1;	// p - used to create the public RSA modulus
	private BigInteger m_RandomPrime2;	// q - used to create the public RSA modulus
	private BigInteger m_PublicProduct;	// e - used as part of the public key
	private BigInteger m_PublicExponent;// n - used as part of the public key
	
	private byte[] m_PublicKey;
	private String m_LastMessage;
	
	private static final int m_nRandomPadLength = 24;
	private static final int m_nPaddedMessageLength = 1024;
	
	/// Public Constructor
	/// initialize PRG with an IV seed
	public RsaServer() {
		m_PRG = new Random(1);
	}
	
	/// Generate a public key that is about the size 1024 bits
	public void generatePublicKey() {
		//Generate two random large primes
		BigInteger p1 = new BigInteger(512, 99, m_PRG);
		BigInteger p1minus1 = p1.subtract(BigInteger.ONE);
		this.setRandomPrime1(p1);
		
		BigInteger p2 = new BigInteger(512, 99, m_PRG);
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
		
		// determine a sufficient value for the public exponent (default e = 3)
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
		
		System.out.println("Alice calculates and shares: ");
		System.out.println("n = " + n.toString());
		System.out.println("e = " + publicExponent.toString());
	}
	
	/// Recieve the incoming ciphertext and decrypt with the private key
	/// @Param bytesCiphertext - incoming ciphertext block
	public void receiveCiphertext(byte[] bytesCiphertext, boolean isPadded) {
		// convert byte blocks to big integer to perform mod power
		BigInteger biCiphertext = new BigInteger(1, bytesCiphertext);
		
		// perform modular exponentiation to retrieve the message
		System.out.println("Alice receives c and decrypts with private key");
		BigInteger biMessage = biCiphertext.modPow(this.getPrivateKey(), this.getPublicProduct());
		
		// if the message is padded, unpad it through OAEP
		if(isPadded) {
			byte[] bytesPaddedMessage = biMessage.toByteArray();
			
			int byteIndexEndOfX = (int)((m_nPaddedMessageLength - m_nRandomPadLength) / 8);
			int byteIndexEndOfY = (int)((m_nPaddedMessageLength) / 8);
			int byteRandomPadLength = (int)(m_nRandomPadLength/8);
			
			byteIndexEndOfX = byteIndexEndOfX + 1;
			byteIndexEndOfY = byteIndexEndOfY + 1;
			
			// get byte arrays from fixed lengths
			byte[] X = null;
			byte[] Y = null;
			
			System.out.print("\nMessage = ");
			RsaUtility.printBytes(bytesPaddedMessage);
			
			// get X and Y subsets from incoming block
			try {
				X = getByteSubset(bytesPaddedMessage, 0, (byteIndexEndOfX-1));
				Y = getByteSubset(bytesPaddedMessage, (byteIndexEndOfX), byteIndexEndOfY);
				
				System.out.println("\nX: " + 0 + " to " + (byteIndexEndOfX - 1));
				System.out.println("Y: " + byteIndexEndOfX + " to " + byteIndexEndOfY);
				
			// catch any array out of bound exceptions
			} catch (Exception ex) {
				System.out.println("Error");
				return;
			}
			
			//recover the random string r = Y XOR H(X)
			byte[] HofX = null;
			try {
				MessageDigest hash512 = MessageDigest.getInstance("SHA-512"); // INSPECT SEED FOR THIS DIGEST >> 00000000X....
				HofX = RsaUtility.maskGenerationFunction(X, byteRandomPadLength, hash512);
			} catch (NoSuchAlgorithmException e) {
				System.out.println("Error");
				return;
			}
			
			BigInteger biY = new BigInteger(1, Y);
			BigInteger biHofX = new BigInteger(1, HofX);
			
			System.out.print("\nServer Y    = ");
			RsaUtility.printBytes(Y);
			System.out.print("\nServer H(X) = ");
			RsaUtility.printBytes(HofX);
			
			byte[] r = biY.xor(biHofX).toByteArray();
			System.out.print("\nServer r    = ");
			r = RsaUtility.getEndingBytes(r, 3);
			RsaUtility.printBytes(r);
			
		}
		
		//convert BigInteger back to string message
		String strMessage = new String(biMessage.toByteArray());
		System.out.println("*ALICE-Private* Decrypted Message: " + strMessage);
		this.setLastDecryptedMessage(strMessage);
	}
	
	
	private byte[] getByteSubset(byte[] block, int firstIndex, int lastIndex) {
		if((lastIndex - firstIndex) < 0) {
			return null;
		}
		int blockLength = lastIndex - firstIndex;
		byte[] newBlock = new byte[blockLength];
		for(int i = 0; i < blockLength; i++) {
			newBlock[i] = block[firstIndex + i];
		}
		return newBlock;
	}
	
	/* Public Access functions */
	
	public BigInteger PUBLISH_PublicProduct() {
		return this.m_PublicProduct;
	}
	
	public BigInteger PUBLISH_PublicExponent() {
		return this.m_PublicExponent;
	}
	
	public String PUBLISH_LastDecryptedMessage() {
		return this.m_LastMessage;
	}
	
	private BigInteger getPrivateKey() {
		return m_PrivateKey;
	}

	/*SETTERS & GETTERS*/
	
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
		return this.m_LastMessage;
	}
	
	private void setLastDecryptedMessage(String lastMessage) {
		this.m_LastMessage = lastMessage;
	}
}