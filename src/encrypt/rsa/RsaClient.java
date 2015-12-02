/*
 * @FileName: RsaClient.java
 * 
 * @Date: November 2015
 * @Author: Michael Bradley, Matthew de la Rosa
 * 
 * @Description: RsaClient is responsible for receiving the public key, and generating
 * 		a Ciphertext for a corresponding message. In a secure transaction, the RsaClient
 * 		should also pad their message properly in order to prevent any malleable attacks 
 */

package encrypt.rsa;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.Scanner;
import encrypt.rsa.util.RsaUtility;

public class RsaClient {
	
	private Random m_PRG;
	private String m_strMessage; // message to be sent
	
	private BigInteger m_biServerPublicProduct;
	private BigInteger m_biServerPublicExponent;
		
	private static final int m_nRandomPadLength = 24;
	private static final int m_nPaddedMessageLength = 1024;

	/// Public Constructor
	/// Initialize the random oracle with an IV seed value
	public RsaClient() {
		m_PRG = new Random(1);
	}
	
	/// get a sample input string from the console
	private String promptForMessage()
	{	
		System.out.println("Client - Input a message: ");
		Scanner scanner = new Scanner(System.in);
		String incomingMesssage = scanner.nextLine();
		String message = incomingMesssage.toString();
		scanner.close();
		return message;
	}
	
	/// Get the public key from an RsaServer and store it
	/// @Param publicProduct - n value from the RsaServer
	/// @Param publicExponent - e value from the RsaServer
	public void receivePublicKey(BigInteger publicProduct, BigInteger publicExponent) {
		this.setServerPublicProduct(publicProduct);
		this.setServerPublicExponent(publicExponent);
	}
	
	/// Optimal Asymmetric Encryption Padding
	/// Apply the OAEP Padding scheme to the message in order to prevent
	/// malleable attacks and introduce non-deterministic properties using the random oracle
	private byte[] padMessage(byte[] messageToPad)
	{
		//pad m with k1 zeroes
		byte[] paddedMessage = null;
		int messageByteLength = (int)(m_nPaddedMessageLength / 8);
		byte[] m = RsaUtility.appendZeroValueBytes(messageToPad, messageByteLength); // pad m with zeros
		
		// generate r as a k0-length string
		byte[] r = new BigInteger((m_nRandomPadLength), m_PRG).toByteArray();
		int randomPadByteLength = (int)(m_nRandomPadLength / 8);
		r = RsaUtility.appendZeroValueBytes(r, randomPadByteLength); // pad r with zeros
		
		//hash and expand r to n - k0 bits using G
		byte[] GofR = null;
		int hashByteLength = messageByteLength - randomPadByteLength;
		try {
			MessageDigest hash256 = MessageDigest.getInstance("SHA-256");
		    GofR = RsaUtility.maskGenerationFunction(r, hashByteLength ,hash256);		    
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		//XOR m and G(r)
		BigInteger biM = new BigInteger(1, m);
		BigInteger biGofR = new BigInteger(1, GofR);
		BigInteger biX = biM.xor(biGofR);
		byte[] X = biX.toByteArray();
		X = RsaUtility.getEndingBytes(X, hashByteLength);
		
		//reduce X to k0 bits
		byte[] HofX = null;
		try {
			MessageDigest hash512 = MessageDigest.getInstance("SHA-512");
			HofX = RsaUtility.maskGenerationFunction(X, randomPadByteLength, hash512);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		System.out.print("Client r    = ");
		RsaUtility.printBytes(r);
		
		System.out.print("\nClient H(X) = ");
		RsaUtility.printBytes(HofX);
		
		
		
		//XOR r and H(X)
		BigInteger biR = new BigInteger(1, r);
		BigInteger biHofX = new BigInteger(1, HofX);
		BigInteger birXORhOfX = biR.xor(biHofX);
		byte[] Y = birXORhOfX.toByteArray();
		Y = RsaUtility.getEndingBytes(Y, randomPadByteLength);
		
		System.out.print("\nClient Y    = ");
		RsaUtility.printBytes(Y);
		
		//concat X and Y
		paddedMessage = RsaUtility.concatenateByte(X, Y);
		
		System.out.print("\nClient Msg  = ");
		RsaUtility.printBytes(paddedMessage);
		System.out.print("\nLength Msg  = " + paddedMessage.length);
		return paddedMessage;
	}
	
	
	/// prompt the user for a new message
	private void createNewMessage()
	{
		String m = promptForMessage();
		this.setMessage(m);
	}
	
	/// set the given parameter as the message
	private void createNewMessage(String newMessage)
	{
		this.setMessage(newMessage);
	}
	
	/// generate a new ciphertext by prompting the user for console input
	public byte[] getNewCiphertext(boolean isPadded)
	{
		createNewMessage();
		byte[] bytesCiphertext = null;
		
		// ensure that there is a message to pad
		if(this.getMessage() != null) {
			// create bytes for message
			byte[] bytesMessage = null;
			bytesMessage = this.getMessage().getBytes();
			
			// calculate the ciphertext for the padded message
			if(isPadded) {
				byte[] bytesPaddedMessage = null;
				bytesPaddedMessage = padMessage(bytesMessage);
				BigInteger biPaddedMessage = new BigInteger(1, bytesPaddedMessage);
				BigInteger biCiphertext = biPaddedMessage.modPow(this.getServerPublicExponent(), this.getServerPublicProduct());
				bytesCiphertext = biCiphertext.toByteArray();
				
				System.out.print("\n*padded Message: ");
				RsaUtility.printBytes(bytesPaddedMessage);
				
				System.out.println("\n*padded message length: " + bytesPaddedMessage.length);
				
				System.out.print("\n*ciphertext: ");
				RsaUtility.printBytes(bytesCiphertext);
				
				System.out.println("\n*ciphertext length: " + bytesCiphertext.length);
				
			// calculate the ciphertext for the unpadded message
			} else {
				BigInteger biMessage = new BigInteger(1, bytesMessage); 
				BigInteger biCiphertext = biMessage.modPow(this.getServerPublicExponent(), this.getServerPublicProduct());			
				bytesCiphertext = biCiphertext.toByteArray();
			}			
			return bytesCiphertext;
		
		} else {
			return null; // no message to send, no ciphertext to return
		}
	}
	
	
	
	/// generate a new ciphertext by prompting the user for console input
		public byte[] getNewCiphertext(String message, boolean isPadded)
		{
			this.setMessage(message);
			byte[] bytesCiphertext = null;
			
			// ensure that there is a message to pad
			if(this.getMessage() != null) {
				// create bytes for message
				byte[] bytesMessage = null;
				bytesMessage = this.getMessage().getBytes();
				
				// calculate the ciphertext for the padded message
				if(isPadded) {
					byte[] bytesPaddedMessage = null;
					bytesPaddedMessage = padMessage(bytesMessage);
					BigInteger biPaddedMessage = new BigInteger(1, bytesPaddedMessage);
					BigInteger biCiphertext = biPaddedMessage.modPow(this.getServerPublicExponent(), this.getServerPublicProduct());
					bytesCiphertext = biCiphertext.toByteArray();
					
					
				// calculate the ciphertext for the unpadded message
				} else {
					BigInteger biMessage = new BigInteger(1, bytesMessage); 
					BigInteger biCiphertext = biMessage.modPow(this.getServerPublicExponent(), this.getServerPublicProduct());			
					bytesCiphertext = biCiphertext.toByteArray();
				}			
				return bytesCiphertext;
			
			} else {
				return null; // no message to send, no ciphertext to return
			}
		}
		
	
	/* PUBLIC Methods & Access functions */
	public String PUBLISH_Message() {
		return this.getMessage();
	}
	
	/* GETTERS & SETTERS */


	private String getMessage() {
		return m_strMessage;
	}


	private void setMessage(String m_strMessage) {
		this.m_strMessage = m_strMessage;
	}
	
	protected final BigInteger getServerPublicProduct() {
		return m_biServerPublicProduct;
	}


	protected final void setServerPublicProduct(BigInteger m_biServerPublicProduct) {
		this.m_biServerPublicProduct = m_biServerPublicProduct;
	}


	protected final BigInteger getServerPublicExponent() {
		return m_biServerPublicExponent;
	}


	protected final void setServerPublicExponent(BigInteger m_biServerPublicExponent) {
		this.m_biServerPublicExponent = m_biServerPublicExponent;
	}
}
