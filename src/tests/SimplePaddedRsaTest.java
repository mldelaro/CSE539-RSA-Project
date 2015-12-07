/*
 * @FileName: MalleableAttackTest.java
 * 
 * @Date: November 2015
 * @Author: Michael Bradley, Matthew de la Rosa
 * 
 * @Description: Simulate a simple encrypt/decrypt of a padded message between bob and alice
 */

package tests;

import static org.junit.Assert.*;
import java.math.BigInteger;
import org.junit.Test;

import encrypt.rsa.RsaClient;
import encrypt.rsa.RsaServer;
import encrypt.rsa.util.RsaUtility;

public class SimplePaddedRsaTest {

	private static RsaClient bob;
	private static RsaServer alice;

	// public key from alice
	private BigInteger publicProduct;
	private BigInteger publicExponent;

	@Test
	public void performEncryptAndDecrypt() {

		// Initialize Alice and publish her public key
		System.out.println("Initializing server... ");
		alice = new RsaServer();
		System.out.println("Server generating public key... ");
		alice.generatePublicKey();
		System.out.println("Server publishing key... ");
		publicProduct = alice.PUBLISH_PublicProduct();
		publicExponent = alice.PUBLISH_PublicExponent();

		// Initialize Bob and recieve Alice's public key
		System.out.println("Initializing client... ");
		bob = new RsaClient();
		System.out.println("Client receiving public key...");
		bob.receivePublicKey(publicProduct, publicExponent);

		// Bob generates a padded message ciphertext to send to alice
		System.out.println("Client generating ciphertext... ");
		byte[] ciphertext = bob.getNewCiphertext(true, false); // true = padded

		System.out.print("\n*Ciphertext: ");
		RsaUtility.printBytes(ciphertext);

		// Alice receives Bob's ciphertext
		System.out.println("Server getting ciphertext... ");
		alice.receiveCiphertext(ciphertext, true); // true = padded message

		// Alice and bob publish their messages
		System.out.println("\nPublishing results... ");
		System.out.println("Bob's Sent Message: " + bob.PUBLISH_Message());
		System.out.println("Alice's Received Message: " + alice.PUBLISH_LastDecryptedMessage());

		assertEquals(bob.PUBLISH_Message(), alice.PUBLISH_LastDecryptedMessage());

		System.out.println("DONE");
	}

}
