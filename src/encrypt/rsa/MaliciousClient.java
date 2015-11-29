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
			System.out.println("Eve edits message: " + new String(this.getSniffedCiphertext()));
			BigInteger biCiphertext = new BigInteger(1, this.getSniffedCiphertext());
			BigInteger biPayload = biCiphertext.multiply(BigInteger.valueOf(2)
												.modPow(super.getServerPublicExponent(),
														super.getServerPublicProduct()));
			
			System.out.println("Eve creates a payload: " + new String(biPayload.toByteArray()));
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
