import java.io.Console;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;


public class RsaRunner {

	public static void main(String[] args) {
		//1, 4, 7, 11
		Random random = new Random(1);
		Scanner a = new Scanner(System.in); //TODO: Check to see if scanner is secure input
		
		
		System.out.println("Bob wants to send a message: ");
		//String read = a.nextLine();
		int m = 1234;//Integer.parseInt(read);
				
		//TODO: Generate a large, prime number?
		System.out.println("Alice generates a prime number: ");
		BigInteger p1 = new BigInteger(50, 99, random);
		BigInteger p1minus1 = p1.subtract(BigInteger.ONE);
		System.out.println(p1.toString());
		
		System.out.println("Alice generates another prime number: ");
		BigInteger p2 = new BigInteger(50, 99, random);
		BigInteger p2minus1 = p2.subtract(BigInteger.ONE);
		System.out.println(p2.toString());
		
		System.out.println("Alice multiplies them together: ");
		BigInteger n = p1.multiply(p2);
		System.out.println(n.toString());
		
		System.out.println("Alice calculates phi(n): ");
		BigInteger phiOfN = p1minus1.multiply(p2minus1);
		System.out.println(phiOfN.toString());
		
		System.out.println("Alice picks a public exponent: ");
		BigInteger publicExponent = BigInteger.ZERO;
		publicExponent = publicExponent.add(BigInteger.ONE);
		publicExponent = publicExponent.add(BigInteger.ONE);
		publicExponent = publicExponent.add(BigInteger.ONE);		
		
		/*TODO: Expand on Euclid's extended algorithm
		 * Find a suitable public 'e' (e = 3 is sufficient for now)
		while(publicExponent.gcd(phiOfN).compareTo(BigInteger.ONE) != 0 ||
				publicExponent.compareTo(BigInteger.ONE) == 0) {
			publicExponent = new BigInteger(10, random);
		}*/
		System.out.println(publicExponent.toString() + "** " + publicExponent.gcd(phiOfN));
		
		System.out.println("Alice calculates PRIVATE KEY: ");
		BigInteger two = BigInteger.valueOf(5);
		BigInteger one = BigInteger.valueOf(1);
		BigInteger privateKey = two.multiply(phiOfN);
		privateKey = privateKey.add(one);
		privateKey = privateKey.divide(publicExponent);
		System.out.println(privateKey.toString());
		
		System.out.println("Alice calculates Shares: ");
		System.out.println("n = " + n.toString());
		System.out.println("e = " + publicExponent.toString());
		
		System.out.println("Bob encrypts his message");
		BigInteger c = BigInteger.valueOf(m).modPow(publicExponent, n);
		System.out.println("c = m^e mod n= " + c);
		
		System.out.println("Alice receives c and decrypts with private key");
		BigInteger m2 = c.modPow(privateKey, n);
		System.out.println("c = m^e mod n= " + m2);

		System.out.println("DONE");
	}
}
