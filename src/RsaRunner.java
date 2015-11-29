import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RsaRunner {
	
	//private static final Logger logger = Logger.getLogger(RsaRunner.class.getCanonicalName());
	private static RsaClient bob; //static is secure?
	private static RsaServer alice;

	public static void main(String[] args) {
		//Seeds that work? 1, 4, 7, 11
		Random random = new Random(1);
		Scanner a = new Scanner(System.in); //TODO: Check to see if scanner is secure input
		
		System.out.println("Initializing server... ");
		alice = new RsaServer();
		System.out.println("Server generating public key... ");
		alice.generatePublicKey();
		
		System.out.println("Initializing client... ");
		bob = new RsaClient();
		System.out.println("Client receiving public key...");
		bob.receivePublicKey(alice.getPublicProduct(), alice.getPublicExponent());
		
		System.out.println("Client generating ciphertext... ");
		byte[] ciphertext = bob.getNewCiphertext();
		BigInteger biCiphertext = new BigInteger(1, ciphertext);
		String testval = new String(biCiphertext.toByteArray());
		System.out.println("Message: " + testval);		
		
		System.out.println("Server getting ciphertext... ");
		alice.receiveCiphertext(ciphertext);		

		System.out.println("DONE");
	}
}
