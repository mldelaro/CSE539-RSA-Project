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

		LargeIntBitArray v1 = new LargeIntBitArray(8);
		LargeIntBitArray v2 = new LargeIntBitArray(4);
		LargeIntBitArray v3 = v1.minus(v2);
		System.out.printf("%s\n",v3.toInt());
		
		
		/*LargeIntBitArray teeest = new LargeIntBitArray(123123123);

		char[] death = teeest.toCharArray();
		String death2 = new String(death);
		System.out.printf("%s %d\n",  death2, death2.length());
		System.out.printf("%s\n",teeest.toInt());
		System.out.printf("%s\n",teeest.toString());
		String instr = (char)7 + "Vµ³";
		teeest.fromCharArray(instr.toCharArray());
		System.out.printf("%s\n",teeest.toString());
		System.out.printf("%d\n",teeest.toInt());
		
		LargeIntBitArray test2 = teeest.plus(teeest);
		System.out.printf("%s\n",test2.toString());
		test2 = test2.lshift(18);
		System.out.printf("%s\n",test2.toString());
		test2 = test2.rshift(17);
		System.out.printf("%s\n",test2.toString());
		System.out.printf("%d\n",test2.toInt());
		test2 = test2.multiply(3);
		System.out.printf("%d\n",test2.toInt());
		
		LargeIntBitArray test3 = new LargeIntBitArray(15537);
		test3 = test3.square();
		System.out.printf("%d\n",test3.toInt());*/
		
		/*
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
		
		System.out.println("DONE");*/
		
			
	}
}
