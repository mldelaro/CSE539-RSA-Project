package encrypt.rsa;

import java.math.*;

public class LargeInt implements Comparable<LargeInt> {
	
	public static final LargeInt ZERO = new LargeInt(0);
	public static final LargeInt ONE = new LargeInt(1);
	public static final LargeInt TEN = new LargeInt(10);
	
	private boolean[] value;
	
	// Size in bits of the int we're representing.
	// this should be more than 2* the size of the max message, for
	// computational reasons.
	// this is GLOBAL, ACROSS THE ENTIRE IMPLEMENTATION.
	// DO NOT CHANGE THIS
	public static final int SIZE = 2000;
	
	// Initializes to 0
	public LargeInt() {
		value = new boolean[SIZE];
		this.reset();
	}
	
	// Initializes from an integer
	public LargeInt(int initValue) {
		value = new boolean[SIZE];
		this.fromInt(initValue);
	}
	
	// Initializes from a byte array
	public LargeInt(byte[] initValue) {
		value = new boolean[SIZE];
		this.fromByteArray(initValue);
	}
	
	// Initializes from a bit array
	public LargeInt(boolean[] initValue) {
		value = new boolean[SIZE];
		this.setValue(initValue);
	}
	
	// Initializes from another large integer
	public LargeInt(LargeInt initValue) {
		value = new boolean[SIZE];
		this.setValue(initValue.getValue());
	}
	
	// Resets to 0
	public void reset() {
		for (int i = 0; i < SIZE; i++) {
			value[i] = false;
		}
	}
	
	// checks if nonzero, more efficient than compareTo since it's
	// hardcoded
	public boolean nonzero() {
		for (int i = 0; i < SIZE; i++) {
			if (value[i]) return true;
		}
		return false;
	}
	
	// checks if odd
	public boolean odd() {
		return this.value[SIZE-1];
	}
	
	// Sets bit at pos to value
	public void setPos(int pos, boolean b) {
		value[pos] = b;
	}
	
	// Sets value from an integer
	public void fromInt(int v) {	
		int i = SIZE - 1;
		//System.out.printf("%d", SIZE);
		while (v > 0) {
			if (v % 2 == 1) value[i] = true;
			else value[i] = false;
			v = v / 2;
			i--;
		}
	}
	
	// Converts to an integer
	public int toInt() {
		int v = 0;
		int i = SIZE - 1;
		int exp = 0;
		while (i >= 0) {
			if (value[i]) v += Math.pow(2, exp);
			//System.out.printf("%d  ", v);
			i--;
			exp++;
		}
		return v;
	}
	
	/*
	// Sets value from a char* array
	// works on any size up to SIZE/8
	public void fromCharArray(char[] v) {
		this.reset();
		char c;
		int pos = v.length - 1;
		int i = SIZE - 8;
		while (pos >= 0) {
			c = v[pos];
			for (int j = 7; j >= 0; j--) {
				//System.out.printf("%d   ", (int)c);
				//System.out.printf("%d %d,", i, j);
				value[i+j] = (c & (char)1 ) == 1;
				//System.out.printf("%b\n", (c & (char)1 ) == 1);
				c = (char)(c>>1);
			}
			i -= 8;
			pos--;
		}
		
	}
	
	public char[] toCharArray() {
		char[] v = new char[SIZE/8];
		char c;
		for (int pos = 0; pos < SIZE/8; pos++) {
			// Convert each 8 bits into one char
			c = 0;
			for (int i = 0; i < 8; i++) {
				if (value[pos*8+i])
					c += (char)( Math.pow(2, (7-i)) );
			}
			v[pos] = c;
			//System.out.printf("%d ", (int)c);
		}
		return v;
	}
	*/
	
	// Sets value from a byte* array
	// works on any size up to SIZE/8
	public void fromByteArray(byte[] v) {
		this.reset();
		byte c;
		int pos = v.length - 1;
		int i = SIZE - 8;
		while (pos >= 0) {
			c = v[pos];
			for (int j = 7; j >= 0; j--) {
				//System.out.printf("%d   ", (int)c);
				//System.out.printf("%d %d,", i, j);
				value[i+j] = (c & (byte)1 ) == 1;
				//System.out.printf("%b\n", (c & (char)1 ) == 1);
				c = (byte)(c>>1);
			}
			i -= 8;
			pos--;
		}
		
	}
	
	public byte[] toByteArray() {
		byte[] v = new byte[SIZE/8];
		byte c;
		for (int pos = 0; pos < SIZE/8; pos++) {
			// Convert each 8 bits into one char
			c = 0;
			for (int i = 0; i < 8; i++) {
				if (value[pos*8+i])
					c += (byte)( Math.pow(2, (7-i)) );
			}
			v[pos] = c;
			//System.out.printf("%d ", (int)c);
		}
		return v;
	}
	
	// Computes this + whatever and returns it as a large int.
	// We assume no overflow.  i.e. this will break if it overflows
	// since it won't keep track of the carry bit.
	public LargeInt plus(LargeInt v) {
		boolean carry = false;
		boolean[] op2 = v.getValue();
		boolean[] result = new boolean[SIZE];
		
		for (int i = SIZE-1; i >= 0; i--) {
			
			result[i] = value[i] ^ op2[i] ^ carry;
			if ( (value[i] && op2[i]) || (value[i] && carry) || (carry && op2[i]) ) carry = true;
			else carry = false;
		
		}
		
		return new LargeInt(result);
	}
	
	// Computes this - whatever and returns it as a large int.
	// We assume no overflow.  i.e. this will break if it overflows
	// since it won't keep track of the carry bit.
	public LargeInt minus(LargeInt v) {
		boolean borrow = false;
		//System.out.printf("%d\n",this.toInt());
		boolean[] op2 = v.getValue();
		boolean[] result = new boolean[SIZE];
		
		for (int i = SIZE-1 ; i >= 0; i--) {

			result[i] = value[i] ^ op2[i] ^ borrow;
			if (!value[i] && op2[i]) borrow = true;				
			else if (value[i] && !op2[i]) borrow = false;
			
		}
		
		return new LargeInt(result);
	}
	
	// Computes this * whatever and returns it as a large int.
	// We assume no overflow.  i.e. this will break if it overflows
	// since it won't keep track of the carry bit.
	public LargeInt multiply(LargeInt v) {
		boolean[] op2 = v.getValue();
		LargeInt result = new LargeInt();
		
		for (int i = SIZE-1; i >= 0; i--) {
			
			if (op2[i]) {
				result = result.plus(this.lshift(SIZE-1-i));
			}
			//System.out.printf("%d  ", i);
		}
		
		return result;
	}
	
	public LargeInt multiply(boolean[] op2) {
		LargeInt result = new LargeInt();
		
		for (int i = SIZE-1; i >= 0; i--) {
			
			if (op2[i]) {
				result = result.plus(this.lshift(SIZE-1-i));
			}
			//System.out.printf("%d  ", i);
		}
		
		return result;
	}
	
	// Computes division somewhat efficiently using binary search.
	public LargeInt divide(LargeInt d) {
		boolean[] result = new boolean[SIZE];
		//LargeInt result = new LargeInt();
		for (int i = SIZE/2; i<SIZE; i++) {
			
			//result.setPos(i,  true);
			result[i] = true;
			if (this.compareTo(d.multiply(result)) < 0) {
				//result.setPos(i, false);
				result[i] = false;
			}	
			
		}
		
		return new LargeInt(result);
	}
	
	// Computes this mod modulus and returns the result.
	// Used to use successive subtraction, until I tried it with
	// really large numbers, which prompted that ^ algorithm.
	public LargeInt mod(LargeInt modulus) {
		
		LargeInt d = this.divide(modulus);
		LargeInt result =  this.minus(modulus.multiply(d));
		return result; 
		
	}
	
	// Computes this  squared and returns it.
	public LargeInt square() {
		return this.multiply(this);
	}

	// Multiplies a long int with a regular int.
	public LargeInt multiply(int v) {
		return this.multiply(new LargeInt(v));
	}
	
	public LargeInt exp(int v) {
		return this.exp(new LargeInt(v));
	}
	
	// Computes this^e mod modulus using repeated squaring.
	// We now have a method of computing RSA modulus with numbers
	// of arbitrary bit size.
	public LargeInt expmod(LargeInt e, LargeInt modulus) {
		
		// result is always going to be the "latest" square
		LargeInt result = new LargeInt(1);
		LargeInt square = new LargeInt(this).mod(modulus);
		
		// iterate through by dividing e by 2
		// represents computing binary representation of e
		while (e.nonzero()) {
			
			if (e.odd())
				result = result.multiply(square).mod(modulus);

			e = e.rshift(1);
			square = square.multiply(square).mod(modulus);
		}
		
		return result;
	}
	
	// Computes this^e using successive squaring
	// we assume there's no overflow error in this
	public LargeInt exp(LargeInt e) {
		
		// result is always going to be the "latest" square
		LargeInt result = new LargeInt(1);
		LargeInt square = new LargeInt(this);
		
		// iterate through by dividing e by 2
		// represents computing binary representation of e
		while (e.nonzero()) {
			
			if (e.odd())
				result = result.multiply(square);
				e = e.rshift(1);
			square = square.multiply(square);
		}
		
		return result;
	}
	
	// Shifts this left by margin and returns the result
	public LargeInt lshift(int margin) {
		boolean[] result = new boolean[SIZE];
		
		for (int i = 0; i < SIZE; i++) {
			if (i + margin < SIZE)
				result[i] = value[i+margin];
			else
				result[i] = false;
		}
		
		return new LargeInt(result);
	}
	
	// Shifts this right by margin and returns the result
	public LargeInt rshift(int margin) {
		boolean[] result = new boolean[SIZE];
		
		for (int i = SIZE-1; i >= 0; i--) {
			if (i >= margin)
				result[i] = value[i-margin];
			else
				result[i] = false;
		}
		
		return new LargeInt(result);
	}
	
	// AND
	public LargeInt and(LargeInt v) {
		boolean[] result = new boolean[SIZE];
		boolean[] op2 = v.getValue();
		
		for (int i = 0; i < SIZE; i++) result[i] = value[i] & op2[i];
		
		return new LargeInt(result);
	}
	
	// OR
	public LargeInt or(LargeInt v) {
		boolean[] result = new boolean[SIZE];
		boolean[] op2 = v.getValue();
		
		for (int i = 0; i < SIZE; i++) result[i] = value[i] | op2[i];
		
		return new LargeInt(result);
	}
	
	// XOR
	public LargeInt xor(LargeInt v) {
		boolean[] result = new boolean[SIZE];
		boolean[] op2 = v.getValue();
		
		for (int i = 0; i < SIZE; i++) result[i] = value[i] ^ op2[i];
		
		return new LargeInt(result);
	}
	
	// computes gcd via Euclidean algo
	public LargeInt gcd(LargeInt b) {
		
		if (this.compareTo(b) < 0) return b.gcd(this);
		else {
			// assume b less than this
			LargeInt r = this, s = b, t = r.mod(b);
			while (t.compareTo(LargeInt.ZERO) > 0) {
				System.out.printf("\n %d %d %d \n",r.toInt(), s.toInt(), t.toInt());
				r = s;
				s = t;
				t = r.mod(s);
			}
			return s;
		}
	}
	
	/*
	// returns TRUE if this is less than v.
	// (use compareTo instead)
	public boolean lessThan(LargeInt v) {
		boolean[] op2 = v.getValue();

		for (int i = 0; i < SIZE; i++) {
			if (!value[i] && op2[i]) return true;
			else if (value[i] && !op2[i]) return false;
		}
		
		return false;
	}
	*/
	
	// toString
	/*public String toString() {
		char[] string = new char[SIZE];
		for (int i = 0; i < SIZE; i++) {
			if (value[i] == true) string[i] = '1';
			else string[i] = '0';
		}
		String s = new String(string);
		return s;
	}*/
	
	// Writes this in decimal.
	public String toString() {
		
		if (this.compareTo(ZERO) == 0) return "0";
		else {
			StringBuffer s = new StringBuffer();
			
			
			
			
			LargeInt i = this;
			LargeInt j = new LargeInt();
			do {
				j = i.mod(TEN);
				s.append(j.toInt());
				i = i.divide(TEN);
				System.out.printf("%s\n",s);
			} while (i.compareTo(ZERO) > 0);
			return new String(s.reverse());
		}
	}
	
	// compareTo
	public int compareTo(LargeInt v) {
		boolean[] op2 = v.getValue();

		for (int i = 0; i < SIZE; i++) {
			if (!value[i] && op2[i]) return -1;
			else if (value[i] && !op2[i]) return 1;
		}
		
		return 0;
	}
	
	public void setValue(boolean[] newValue) {
		for (int i = 0; i < SIZE; i++)
			value[i] = newValue[i];
	}
	
	public boolean[] getValue() {
		boolean[] returnValue = new boolean[SIZE];
		for (int i = 0; i < SIZE; i++)
			returnValue[i] = value[i];
		return returnValue;
	}
	
}
