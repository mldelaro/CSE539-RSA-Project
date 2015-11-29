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
	public void performEncryptAndDecrypt() {
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
		BigInteger biCiphertext = new BigInteger(1, bytesCiphertext);
		String strCiphertext = new String(biCiphertext.toByteArray());
		System.out.println("Message: " + strCiphertext);
		
		System.out.println("**ATTACK STARTS**");
		System.out.println("Eve gets bob's ciphertext");
		eve.setSniffedCiphertext(bytesCiphertext);
		byte[] payload = eve.startMalleableAttack();
		alice.receiveCiphertext(payload);
		System.out.println("\nPublishing results... ");
		System.out.println("Alice's Received Message: " + alice.PUBLISH_LastDecryptedMessage());
		
		System.out.println("Message Value: " + new BigInteger(1, bytesCiphertext).toString());
		System.out.println("Payload Value: " + new BigInteger(1, payload).toString());
		System.out.println("2m mod n: " + new BigInteger(1, payload).toString());

		/*
		System.out.println("Server getting ciphertext... ");
		alice.receiveCiphertext(bytesCiphertext);
		
		System.out.println("\nPublishing results... ");
		System.out.println("Bob's Sent Message: " + bob.PUBLISH_Message());
		System.out.println("Alice's Received Message: " + alice.PUBLISH_LastDecryptedMessage());
		
		assertEquals(bob.PUBLISH_Message(), alice.PUBLISH_LastDecryptedMessage());
		
		System.out.println("DONE");*/
	}

}
