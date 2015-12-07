/*
 * @FileName: MaliciousClient.java
 * 
 * @Date: November 2015
 * @Author: Michael Bradley, Matthew de la Rosa
 * 
 * @Description: MaliciousClients have the same abilities as regular RsaClients,
 * 				with the extended ability to sniff packets and alter messages and
 * 				ciphertexts they receive to create payloads for RsaServers
 */

package encrypt.rsa;

import java.math.BigDecimal;
import java.math.BigInteger;

public class MaliciousClient extends RsaClient {
	private byte[] m_sniffedCiphertext;

	public byte[] startMalleableAttack() {
		byte[] bytesPayload = null;
		if (this.getSniffedCiphertext() == null) {
			System.out.println("No ciphertext");
			return null; // no ciphertext to transform

		} else {
			System.out.println("*Adversary* Edit message: " + new String(this.getSniffedCiphertext()));
			BigInteger biCiphertext = new BigInteger(1, this.getSniffedCiphertext());
			BigInteger biPayload = biCiphertext.multiply(
					BigInteger.valueOf(2).modPow(super.getServerPublicExponent(), super.getServerPublicProduct()));

			System.out.println("*Adversary* Create payload: " + new String(biPayload.toByteArray()));
			bytesPayload = biPayload.toByteArray();
			return bytesPayload;
		}
	}

	public String startManagersCiphertextAttack() {
		String foundMessage = null;
		if (this.getSniffedCiphertext() == null)  {
			System.out.println("No ciphertext");
			return ""; // no ciphertext to transform
		}
		
		//find the byte length of public modulus n by taking log base 256 where 256^k = n or 2^(8*k)=n
		BigInteger biTwo = BigInteger.valueOf(2);
		int nExponentB = 8*(79-1); // TODO log function to solve for k
		BigInteger B = biTwo.pow(nExponentB);
		System.out.println("Calculated B: " + B.toString());
		
		// Calculate the B value: the max value that spans the length of the message space minus 1 octet
		System.out.println("length of n: " + this.getServerPublicProduct().toByteArray().length);
		
		// oracle to vulnerable implementation of decrypt with padding
		// receiveCiphertextWithErrorReturn(bytesPayload, true); //candidate
		// payload

		return "";
	}

	public void setSniffedCiphertext(byte[] c) {
		this.m_sniffedCiphertext = c;
	}

	public byte[] getSniffedCiphertext() {
		return this.m_sniffedCiphertext;
	}
}
