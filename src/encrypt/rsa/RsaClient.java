package encrypt.rsa;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
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
		byte[] paddedMessage = null;
		int messageByteLength = (int)(m_nPaddedMessageLength / 8);
		byte[] m = appendZeroValueBytes(messageToPad, messageByteLength); // pad m with zeros
		
		// generate r as a k0-length string
		byte[] r = new BigInteger((m_nRandomPadLength), m_PRG).toByteArray();
		int randomPadByteLength = (int)(m_nRandomPadLength / 8);
		r = appendZeroValueBytes(r, randomPadByteLength); // pad r with zeros
		
		//hash and expand r to n - k0 bits using G
		byte[] GofR = null;
		int hashByteLength = messageByteLength - randomPadByteLength;
		try {
			MessageDigest hash256 = MessageDigest.getInstance("SHA-256");
		    GofR = maskGenerationFunction(r, hashByteLength ,hash256);		    
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		//XOR m and G(r)
		BigInteger biM = new BigInteger(1, m);
		BigInteger biGofR = new BigInteger(1, GofR);
		BigInteger biX = biM.xor(biGofR);
		byte[] X = biX.toByteArray();
		X = getEndingBytes(X, hashByteLength);
		
		//reduce X to k0 bits
		byte[] HofX = null;
		try {
			MessageDigest hash512 = MessageDigest.getInstance("SHA-512");
			HofX = maskGenerationFunction(X, randomPadByteLength, hash512);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		//XOR r and H(X)
		BigInteger biR = new BigInteger(1, r);
		BigInteger biHofX = new BigInteger(1, HofX);
		BigInteger birXORhOfX = biR.xor(biHofX);
		byte[] Y = birXORhOfX.toByteArray();
		
		//concat X and Y
		paddedMessage = concatenateByte(X, Y);
		
		System.out.println("**PAD** - resulting pad with size: " + paddedMessage.length);
		printBytes(paddedMessage);
		return messageToPad;
	}
	
	/* takes an input block and a desired output length 
	 * uses the SHA-2 family based hash function to 
	 * 
	 */
	private byte[] maskGenerationFunction(byte[] seed, int desiredByteLength, MessageDigest hashFunction ) {
		byte[] T = new byte[desiredByteLength]; //create empty byte array
		int counter = 0;
		double digestByteSize = (double)(hashFunction.getDigestLength() / 8.0d);
		double temp = (desiredByteLength / digestByteSize);
		int endIndex = (int)(Math.ceil(temp));
		for(counter = 0; counter < endIndex; counter++) {
			// convert count to 4-byte array
			byte[] byteCounter = intToByteArray(counter);
			
			//concatenate seed and counter
			byte[] blockToHash;
			blockToHash = concatenateByte(seed, byteCounter);
			
			//hash the concatenation
			hashFunction.update(blockToHash);
			byte[] blockToConcatenate;
			blockToConcatenate = hashFunction.digest();
			
			// add to octet string
			T = concatenateByte(T, blockToConcatenate);
		}
		
		byte[] output = getEndingBytes(T, desiredByteLength);
		//return leading desired number of bytes
		return output;
	}
	
	private byte[] intToByteArray(int value) {
		return ByteBuffer.allocate(4).putInt(value).array();
	}
	
	// for use in mask generation function (output)
	private byte[] getEndingBytes(byte[] block, int bytesToKeep) {
		byte[] outputBlock = new byte[bytesToKeep];
		
		if(bytesToKeep > block.length) {
			outputBlock = appendZeroValueBytes(block, bytesToKeep);
		} else {
			for(int i = 0; i < bytesToKeep; i++) {
				int indexToCopy = (block.length - (bytesToKeep - i));
				outputBlock[i] = block[indexToCopy];
			}
		}
		
		return outputBlock;
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
	
	private byte[] appendZeroValueBytes(byte[] blockA, int desiredByteLength) {
		int oldByteLength = blockA.length;
		
		if(oldByteLength < desiredByteLength) {
			int neededZeroBlocks = (desiredByteLength- oldByteLength) ;
			byte[] paddedBlock = new byte[desiredByteLength];
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
