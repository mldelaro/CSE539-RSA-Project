/*
 * @FileName: ManagersCiphertextAttackTest.java
 * 
 * @Date: November 2015
 * @Author: Michael Bradley, Matthew de la Rosa
 * 
 * @Description: Simulate a chosen ciphertext attack on the padded message between
 * 				Alice and Bob. This attack underlines the importance of having a padded scheme
 * 				that is properly implemented to not leak any side information.
 */

package tests;

import java.math.BigInteger;
import org.junit.Test;

import encrypt.rsa.MaliciousClient;
import encrypt.rsa.RsaClient;
import encrypt.rsa.RsaServer;

public class ManagersCiphertextAttackTest {
	
	private static RsaClient bob;
	private static MaliciousClient eve;
	private static RsaServer alice;
	
	// public key from alice
	private BigInteger publicProduct;
	private BigInteger publicExponent;
	
	@Test
	public void performMalleableAttackTest() {

		// Initialize Alice and publish her public key
		System.out.println("Initializing server... ");
		alice = new RsaServer();
		System.out.println("Server generating public key... ");
		alice.generatePublicKey();
		System.out.println("Server publishing key... ");
		publicProduct = alice.PUBLISH_PublicProduct();
		publicExponent = alice.PUBLISH_PublicExponent();

		// Initialize Bob and retrieve the public key
		System.out.println("Initializing client bob... ");
		bob = new RsaClient();
		System.out.println("Bob receiving public key...");
		bob.receivePublicKey(publicProduct, publicExponent);

		// Initialize Eve and retrieve the public key
		System.out.println("Initializing client eve... ");
		eve = new MaliciousClient();
		System.out.println("Eve receiving public key...");
		eve.receivePublicKey(publicProduct, publicExponent);

		// Ask bob to generate a ciphertext that is NOT PADDED
		System.out.println("Client generating ciphertext for message \"12341234\"... ");
		byte[] bytesBobsCiphertext = bob.getNewCiphertext("12341234", true); // true = padding

		// Begin Eve's malleable attack on the unpadded message
		System.out.println("**ATTACK STARTS**");
		System.out.println("Eve gets bob's ciphertext");
		eve.setSniffedCiphertext(bytesBobsCiphertext);
		String evesDecryptedMessage = eve.startManagersCiphertextAttack();

		// Send payload to alice
		System.out.println("Eve has decrypted bobs message...");
		System.out.println("Eve's message: " + evesDecryptedMessage);
		alice.receiveCiphertext(bytesBobsCiphertext, true); // true = message padded

		// Get results from received payload
		System.out.println("\nPublishing results... ");
		System.out.println("Alice's Received Message: " + alice.PUBLISH_LastDecryptedMessage());
		System.out.println("DONE");
	}
}
