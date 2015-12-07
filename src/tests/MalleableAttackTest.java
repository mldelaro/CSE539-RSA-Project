/*
 * @FileName: MalleableAttackTest.java
 * 
 * @Date: November 2015
 * @Author: Michael Bradley, Matthew de la Rosa
 * 
 * @Description: Simulate a malleable attack on the non-padded message between
 * 				Alice and Bob. This attack underlines the importance of having a padded scheme
 */

package tests;

import java.math.BigInteger;
import org.junit.Test;

import encrypt.rsa.MaliciousClient;
import encrypt.rsa.RsaClient;
import encrypt.rsa.RsaServer;

public class MalleableAttackTest {

	private static RsaClient bob;
	private static MaliciousClient eve;
	private static RsaServer alice;

	// public key from alice
	private BigInteger publicProduct;
	private BigInteger publicExponent;
	
	@Test
	public void performMalleableAttackTestPadded() {
		
		System.out.println("Performing malleable attack on padded message...");

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
		byte[] bytesBobsCiphertext = bob.getNewCiphertext("12341234", true, true); // padding

		// Begin Eve's malleable attack on the unpadded message
		System.out.println("**ATTACK STARTS**");
		System.out.println("Eve gets bob's ciphertext");
		eve.setSniffedCiphertext(bytesBobsCiphertext);
		byte[] evesPayload = eve.startMalleableAttack();

		// Send payload to alice
		System.out.println("Eve sends payload to alice...");
		alice.receiveCiphertext(evesPayload, true); // false = message padded

		// Get results from received payload
		System.out.println("\nPublishing results... ");
		System.out.println("Alice's Received Message: " + alice.PUBLISH_LastDecryptedMessage());
		System.out.println("DONE");
	}

	@Test
	public void performMalleableAttackTest() {
		
		System.out.println("Performing malleable attack on unpadded message...");

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
		byte[] bytesBobsCiphertext = bob.getNewCiphertext("12341234", false, true); // no padding

		// Begin Eve's malleable attack on the unpadded message
		System.out.println("**ATTACK STARTS**");
		System.out.println("Eve gets bob's ciphertext");
		eve.setSniffedCiphertext(bytesBobsCiphertext);
		byte[] evesPayload = eve.startMalleableAttack();

		// Send payload to alice
		System.out.println("Eve sends payload to alice...");
		alice.receiveCiphertext(evesPayload, false); // false = message not
														// padded

		// Get results from received payload
		System.out.println("\nPublishing results... ");
		System.out.println("Alice's Received Message: " + alice.PUBLISH_LastDecryptedMessage());
		System.out.println("DONE");
	}
}
