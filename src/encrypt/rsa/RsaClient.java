package encrypt.rsa;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.Scanner;



public class RsaClient {
	
	//TODO: Check security for member initialization
	private Random m_PRG;
	private String m_strMessage;
	
	private BigInteger m_biServerPublicProduct;
	private BigInteger m_biServerPublicExponent;
		
	private static final int m_nRandomPadLength = 24;
	private static final int m_nMessageLength = 1024;
	private static final int m_nPaddedMessageLength = 1048;

	// Public Constructor
	public RsaClient() {
		m_PRG = new Random(1);
	}
	
	
	//TODO: Check for secure user input
	private String promptForMessage()
	{	
		System.out.println("Client - Input a message: ");
		Scanner scanner = new Scanner(System.in);
		String message = scanner.nextLine(); // sanitize?
		scanner.close();
		return message;
	}
	
	//TODO: send over padded scheme?
	public void receivePublicKey(BigInteger publicProduct, BigInteger publicExponent) {
		this.setServerPublicProduct(publicProduct);
		this.setServerPublicExponent(publicExponent);
	}
	
	// OAETP
	private byte[] padMessage(byte[] messageToPad)
	{		
		System.out.println("**PAD** - messageToPad: " + new BigInteger(messageToPad).toString());
		System.out.println("**PAD** - messageLength: " + m_nMessageLength);
		
		//pad m with k1 zeroes
		byte[] paddedMessage = new byte[m_nPaddedMessageLength];
		byte[] m = appendZeroValueBytes(messageToPad, m_nMessageLength); // pad m with zeros
		
		// generate r as a k0-length string
		byte[] r = new BigInteger((m_nRandomPadLength), m_PRG).toByteArray();
		r = appendZeroValueBytes(r, m_nRandomPadLength); // pad r with zeros
		
		//hash r to n - k0 bits using G
		int hashBitLength = m_nMessageLength - m_nRandomPadLength;
		
		System.out.println("**PAD** - hashing r to length n-k0: " + hashBitLength);
		System.out.println("**PAD** - resulting hash G(r):");
		printBytes(paddedMessage);
		
		//XOR m and G(r)
		
		//reduce X to k0 bits
		
		//XOR r and H(X)
		
		//concat X and Y
		paddedMessage = concatenateByte(m, r);
		
		System.out.println("**PAD** - resulting pad:");
		printBytes(paddedMessage);
		return messageToPad;
	}
	/*
	private byte[] getByteSubset(byte[] blockSet, int firstIndex, int lastIndex) {
		if((lastIndex - firstIndex) < 0) {
			return null;
		}
		
		int setIndex = 0;
		int blockLength = lastIndex - firstIndex;
		
		byte[] blockSubset = new byte[blockLength];
		
		for(setIndex = firstIndex; setIndex < lastIndex; setIndex++) {
			int subsetIndex = setIndex - firstIndex;
			blockSubset[subsetIndex] = blockSet[setIndex];
		}
		
		return blockSubset;
	}*/
	
	private void printBytes(byte[] block) {
		for(int i = 0; i < block.length; i++) {
			String s1 = String.format("%8s", Integer.toBinaryString(block[i] & 0xFF)).replace(' ', '0');
			System.out.print(s1 + " "); // 10000001
		}
	}
	
	private byte[] appendZeroValueBytes(byte[] blockA, int desiredBitLength) {
		int oldBitLength = blockA.length * 8;
		
		if(oldBitLength < desiredBitLength) {
			int neededZeroBlocks = ((desiredBitLength - oldBitLength)/8) ;
			byte[] paddedBlock = new byte[(desiredBitLength / 8)];
			for(int i = 0; i < blockA.length; i++) {
				paddedBlock[i] = blockA[i];
			}
			for(int i = blockA.length; i < neededZeroBlocks; i++) {
				paddedBlock[i] = (byte) 0;
			}
			return paddedBlock;
		} else {
			return blockA;
		}
	}
	
	private byte[] concatenateByte(byte[] blockA, byte[] blockB) {
		int newBlockLength = blockA.length + blockB.length;
		byte[] newBlock = new byte[newBlockLength];
		for(int i = 0; i < blockA.length; i++) {
			newBlock[i] = blockA[i];
		}
		
		for(int i = 0; i < blockB.length; i++) {
			newBlock[i+blockA.length] = blockB[i];
		}
		return newBlock;
	}
	
	private void createNewMessage(String newMessage)
	{
		if(newMessage == null) {
			String m = promptForMessage();
			this.setMessage(m);
		} else {
			this.setMessage(newMessage);
		}
	}
	
	public byte[] getNewCiphertext()
	{
		createNewMessage(null);
		byte[] bytesCiphertext = null;
		
		if(this.getMessage() != null) { //TODO: security regarding accessing private members in public method
			//TODO: check message for null security
			byte[] bytesMessage = null;
			byte[] bytesPaddedMessage = null;
			bytesMessage = m_strMessage.getBytes();// TODO: accessing private member?
			bytesPaddedMessage = padMessage(bytesMessage);
			
			BigInteger biPaddedMessage = new BigInteger(1, bytesPaddedMessage);
			BigInteger biCiphertext = biPaddedMessage.modPow(this.getServerPublicExponent(), this.getServerPublicProduct());			
			bytesCiphertext = biCiphertext.toByteArray();
			
			return bytesCiphertext;
		} else {
			return null;
		}
	}
	
	public String PUBLISH_Message() {
		return this.getMessage();
	}


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
