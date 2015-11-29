package encrypt.rsa;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

public class RsaRunner {
	
	//private static final Logger logger = Logger.getLogger(RsaRunner.class.getCanonicalName());
	private static RsaClient bob; //static is secure?
	private static RsaServer alice;
	
	//public key from alice
	private static BigInteger publicProduct;
	private static BigInteger publicExponent;


	public static void main(String[] args) {
		//Seeds that work? 1, 4, 7, 11		
		System.out.println("Initializing server... ");
		alice = new RsaServer();
		System.out.println("Server generating public key... ");
		alice.generatePublicKey();
		System.out.println("Server publishing key... ");
		publicProduct = alice.PUBLISH_PublicProduct();
		publicExponent = alice.PUBLISH_PublicExponent();
		
		
		System.out.println("Initializing client... ");
		bob = new RsaClient();
		System.out.println("Client receiving public key...");
		bob.receivePublicKey(publicProduct, publicExponent);
		
		System.out.println("Client generating ciphertext... ");
		byte[] ciphertext = bob.getNewCiphertext();
		BigInteger biCiphertext = new BigInteger(1, ciphertext);
		String testval = new String(biCiphertext.toByteArray());
		System.out.println("Message: " + testval);		
		
		System.out.println("Server getting ciphertext... ");
		alice.receiveCiphertext(ciphertext);
		
		System.out.println("\nPublishing results... ");
		System.out.println("Bob's Sent Message: " + bob.PUBLISH_Message());
		System.out.println("Alice's Received Message: " + alice.PUBLISH_LastDecryptedMessage());
		
		assertEquals(bob.PUBLISH_Message(), alice.PUBLISH_LastDecryptedMessage());
		
		System.out.println("DONE");
			
	}
}
