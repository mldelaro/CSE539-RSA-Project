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

import java.math.BigInteger;

public class MaliciousClient extends RsaClient {
	private byte[] m_sniffedCiphertext;
	
	public byte[] startMalleableAttack() {
		byte[] bytesPayload = null;
		if(this.getSniffedCiphertext() == null) {
			System.out.println("No ciphertext");
			return null; //no ciphertext to transform
		
		} else {
			System.out.println("*Eve-Private* Eve edits message: " + new String(this.getSniffedCiphertext()));
			BigInteger biCiphertext = new BigInteger(1, this.getSniffedCiphertext());
			BigInteger biPayload = biCiphertext.multiply(BigInteger.valueOf(2)
												.modPow(super.getServerPublicExponent(),
														super.getServerPublicProduct()));
			
			System.out.println("*Eve-Private* Eve creates a payload: " + new String(biPayload.toByteArray()));
			bytesPayload = biPayload.toByteArray();
			return bytesPayload;
		}
	}
	
	public void setSniffedCiphertext(byte[] c) {
		this.m_sniffedCiphertext = c;
	}
	
	public byte[] getSniffedCiphertext() {
		return this.m_sniffedCiphertext;
	}
}
