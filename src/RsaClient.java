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
	private static final int m_nMessageLength = 100; //TODO: Determine message length

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
	private byte[] padMessage(byte[] messageToPad, int length)
	{
		if(length > 1) { // TODO: Determine smallest message
			return null;
		}
		return messageToPad;
	}
	
	private void createNewMessage()
	{
		String m = null;
		m_strMessage = promptForMessage();
	}
	
	public byte[] getNewCiphertext()
	{
		createNewMessage();
		byte[] bytesCiphertext = null;
		
		if(this.getMessage() != null) { //TODO: security regarding accessing private members in public method
			//TODO: check message for null security
			byte[] bytesMessage = null;
			byte[] bytesPaddedMessage = null;
			bytesMessage = m_strMessage.getBytes();// TODO: accessing private member?
			bytesPaddedMessage = padMessage(bytesMessage, 0);
			
			BigInteger biPaddedMessage = new BigInteger(1, bytesPaddedMessage);
			BigInteger biCiphertext = biPaddedMessage.modPow(this.getServerPublicExponent(), this.getServerPublicProduct());			
			bytesCiphertext = biCiphertext.toByteArray();
			
			return bytesCiphertext;
		} else {
			return null;
		}
	}


	private String getMessage() {
		return m_strMessage;
	}


	private void setMessage(String m_strMessage) {
		this.m_strMessage = m_strMessage;
	}


	private BigInteger getServerPublicProduct() {
		return m_biServerPublicProduct;
	}


	private void setServerPublicProduct(BigInteger m_biServerPublicProduct) {
		this.m_biServerPublicProduct = m_biServerPublicProduct;
	}


	private BigInteger getServerPublicExponent() {
		return m_biServerPublicExponent;
	}


	private void setServerPublicExponent(BigInteger m_biServerPublicExponent) {
		this.m_biServerPublicExponent = m_biServerPublicExponent;
	}
}
