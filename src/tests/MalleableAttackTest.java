package tests;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;

import encrypt.rsa.MaliciousClient;
import encrypt.rsa.RsaClient;
import encrypt.rsa.RsaServer;

public class MalleableAttackTest {
	
	private static RsaClient bob;
	private static MaliciousClient eve;
	private static RsaServer alice;
	
	//public key from alice
	private BigInteger publicProduct;
	private BigInteger publicExponent;
	
	@Test
	public void performMalleableAttackTest() {
		System.out.println("Initializing server... ");
		alice = new RsaServer();
		System.out.println("Server generating public key... ");
		alice.generatePublicKey();
		System.out.println("Server publishing key... ");
		publicProduct = alice.PUBLISH_PublicProduct();
		publicExponent = alice.PUBLISH_PublicExponent();
		
		System.out.println("Initializing clients... ");
		bob = new RsaClient();
		eve = new MaliciousClient();
		System.out.println("Client receiving public key...");
		bob.receivePublicKey(publicProduct, publicExponent);
		eve.receivePublicKey(publicProduct, publicExponent);
		
		System.out.println("Client generating ciphertext... ");
		byte[] bytesCiphertext = bob.getNewCiphertext();
		/*BigInteger biCiphertext = new BigInteger(1, bytesCiphertext);
		String strCiphertext = new String(biCiphertext.toByteArray());
		System.out.println("Message: " + strCiphertext);
		
		System.out.println("**ATTACK STARTS**");
		
		System.out.println("Eve gets bob's ciphertext");
		//PROOF OF CONCEPT - multiplying 2m -> deposit twice as much
		BigInteger biPayload = biCiphertext.multiply(BigInteger.valueOf(2)
											.modPow(publicExponent,
													publicProduct));
		alice.receiveCiphertext(biPayload.toByteArray());
		
		System.out.println("\nPublishing results... ");
		System.out.println("Alice's Received Message: " + alice.PUBLISH_LastDecryptedMessage());
		System.out.println("DONE");*/
	}
}
