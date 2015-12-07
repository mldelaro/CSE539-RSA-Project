package tests;

import static org.junit.Assert.*;

import org.junit.Test;

import encrypt.rsa.LargeInt;

public class LargeIntTest {

	@Test
	public void test16000() {
		
		// Calculate some stuff with numbers that are obviously
		// larger than the machine word size.
		// 16000 bits??
		LargeInt two = new LargeInt(2);
		
		LargeInt three = new LargeInt(3);
		three = three.exp(5000);
		three = three.minus(LargeInt.ONE());

		two = two.expmod(new LargeInt(14000), three);
		
		two = two.rshift(7900);
		assertEquals(two.toInt(), 24862718);

		System.out.println("DONE");
	}
	
}
