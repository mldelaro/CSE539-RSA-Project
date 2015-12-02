package encrypt.rsa.util;

import java.nio.ByteBuffer;
import java.security.MessageDigest;

public final class RsaUtility {
	
	
	/// Take an input block and a desired output length and use the given
	/// hash function in order to lengthen the given seed
	/// @Param seed - initial octet string
	/// @Param desiredByteLength - desired octet string length
	/// @Param MessageDigest - Hash function to concatenate extra values
	public static byte[] maskGenerationFunction(byte[] seed, int desiredByteLength, MessageDigest hashFunction ) {
		byte[] T = new byte[desiredByteLength]; //create empty byte array
		int counter = 0;
		double digestByteSize = (double)(hashFunction.getDigestLength() / 8.0d);
		double temp = (desiredByteLength / digestByteSize);
		int endIndex = (int)(Math.ceil(temp));
		for(counter = 0; counter < endIndex; counter++) {
			// convert count to 4-byte array
			byte[] byteCounter = intToByteArray(counter);
			
			//concatenate seed and counter
			byte[] blockToHash;
			blockToHash = concatenateByte(seed, byteCounter);
			
			//hash the concatenation
			hashFunction.update(blockToHash);
			byte[] blockToConcatenate;
			blockToConcatenate = hashFunction.digest();
			
			// add to octet string
			T = concatenateByte(T, blockToConcatenate);
		}
		
		byte[] output = getEndingBytes(T, desiredByteLength);
		//return leading desired number of bytes
		return output;
	}
	
	/// Helper function prints bytes for a given byte[] block
	/// @Param block - block to print
	public static void printBytes(byte[] block) {
		for(int i = 0; i < block.length; i++) {
			String s1 = String.format("%8s", Integer.toBinaryString(block[i] & 0xFF)).replace(' ', '0');
			System.out.print(s1 + " ");
		}
	}
	
	/// Append a number of zero-valued bytes to the end of the given block
	/// @Param blockA - block to append zeros
	/// @Param desiredByteLength - total number of blocks desired after appending
	public static byte[] appendZeroValueBytes(byte[] blockA, int desiredByteLength) {
		int oldByteLength = blockA.length;
		
		// Do not append blocks if the number of desired bytes is less then the current length
		if(oldByteLength < desiredByteLength) {
			int neededZeroBlocks = (desiredByteLength- oldByteLength) ;
			byte[] paddedBlock = new byte[desiredByteLength];
			for(int i = 0; i < blockA.length; i++) {
				paddedBlock[i] = blockA[i];
			}
			for(int i = blockA.length; i < neededZeroBlocks; i++) {
				paddedBlock[i] = (byte) 0;
			}
			return paddedBlock;
		} else {
			return blockA;
		}
	}
	
	/// Join two byte blocks together
	/// @Param blockA - first block
	/// @Param blockB - second block
	public static byte[] concatenateByte(byte[] blockA, byte[] blockB) {
		int newBlockLength = blockA.length + blockB.length; // create a new block
		byte[] newBlock = new byte[newBlockLength];
		
		// add bytes from first block
		for(int i = 0; i < blockA.length; i++) {
			newBlock[i] = blockA[i];
		}
		
		// add bytes from second block
		for(int i = 0; i < blockB.length; i++) {
			newBlock[i+blockA.length] = blockB[i];
		}
		return newBlock;
	}
	
	/// Get the last blocks from a given block 
	/// @Param block - initial block to truncate from
	/// @Param int - number of bytes to keep form the end
	/// @See Mask Generation Function (output)
	public static byte[] getEndingBytes(byte[] block, int bytesToKeep) {
		byte[] outputBlock = new byte[bytesToKeep];
		
		// append zeroes if the bytes to keep is larger then the block length
		if(bytesToKeep > block.length) {
			outputBlock = appendZeroValueBytes(block, bytesToKeep);
		} else {
			
		// get the last blocks 
			for(int i = 0; i < bytesToKeep; i++) {
				int indexToCopy = (block.length - (bytesToKeep - i));
				outputBlock[i] = block[indexToCopy];
			}
		}
		return outputBlock;
	}

	/// Simple helper function to convert integer into byte[4]
	/// @Param value - integer to convert
	public static byte[] intToByteArray(int value) {
		return ByteBuffer.allocate(4).putInt(value).array();
	}

}
