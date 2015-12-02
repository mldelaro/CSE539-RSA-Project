package encrypt.rsa;

public class LargeIntBitArray {

	private boolean[] value;

	// Size in bits of the int we're representing.
	// this is GLOBAL, ACROSS THE ENTIRE IMPLEMENTATION.
	// DO NOT CHANGE THIS
	public static int SIZE = 1048;

	// Initializes to 0
	public LargeIntBitArray() {
		value = new boolean[SIZE];
		this.reset();
	}

	// Initializes from an integer
	public LargeIntBitArray(int initValue) {
		value = new boolean[SIZE];
		this.fromInt(initValue);
	}

	// Initializes from a bit array
	public LargeIntBitArray(boolean[] initValue) {
		value = new boolean[SIZE];
		this.setValue(initValue);
	}

	public LargeIntBitArray(LargeIntBitArray initValue) {
		value = new boolean[SIZE];
		this.setValue(initValue.getValue());
	}

	// Resets to 0
	public void reset() {
		for (int i = 0; i < SIZE; i++) {
			value[i] = false;
		}
	}

	// Sets value from an integer
	public void fromInt(int v) {
		int i = SIZE - 1;
		while (v > 0) {
			if (v % 2 == 1)
				value[i] = true;
			else
				value[i] = false;
			v = v / 2;
			i--;
		}
	}

	public int toInt() {
		int v = 0;
		int i = SIZE - 1;
		int exp = 0;
		while (i >= 0) {
			if (value[i])
				v += Math.pow(2, exp);
			// System.out.printf("%d ", v);
			i--;
			exp++;
		}
		return v;
	}

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
				// System.out.printf("%d ", (int)c);
				// System.out.printf("%d %d,", i, j);
				value[i + j] = (c & (char) 1) == 1;
				// System.out.printf("%b\n", (c & (char)1 ) == 1);
				c = (char) (c >> 1);
			}
			i -= 8;
			pos--;
		}

	}

	public char[] toCharArray() {
		char[] v = new char[SIZE / 8];
		char c;
		for (int pos = 0; pos < SIZE / 8; pos++) {
			// Convert each 8 bits into one char
			c = 0;
			for (int i = 0; i < 8; i++) {
				if (value[pos * 8 + i])
					c += (char) (Math.pow(2, (7 - i)));
			}
			v[pos] = c;
			// System.out.printf("%d ", (int)c);
		}
		return v;
	}

	// Computes this + whatever and returns it as a bitarray.
	// We assume no overflow. i.e. this will break if it overflows
	// since it won't keep track of the carry bit.
	public LargeIntBitArray plus(LargeIntBitArray v) {
		boolean carry = false;
		boolean[] op2 = v.getValue();
		boolean[] result = new boolean[SIZE];

		for (int i = SIZE - 1; i >= 0; i--) {

			result[i] = value[i] ^ op2[i] ^ carry;
			if ((value[i] && op2[i]) || (value[i] && carry) || (carry && op2[i]))
				carry = true;
			else
				carry = false;

		}

		return new LargeIntBitArray(result);
	}

	// Computes this - whatever and returns it as a bitarray.
	// We assume no overflow. i.e. this will break if it overflows
	// since it won't keep track of the carry bit.
	public LargeIntBitArray minus(LargeIntBitArray v) {
		boolean borrow = false;
		boolean[] op2 = v.getValue();
		boolean[] result = new boolean[SIZE];

		for (int i = SIZE = 1; i >= 0; i--) {

			if (!borrow) {
				result[i] = value[i] ^ op2[i];
				if (!value[i] && op2[i])
					borrow = true;
			}
			if (borrow) {
				result[i] = false;
				if (value[i] && !op2[i])
					borrow = false;

			}

		}

		return new LargeIntBitArray(result);
	}

	// Computes this + whatever and returns it as a bitarray.
	// We assume no overflow. i.e. this will break if it overflows
	// since it won't keep track of the carry bit.
	public LargeIntBitArray multiply(LargeIntBitArray v) {
		boolean[] op2 = v.getValue();
		LargeIntBitArray result = new LargeIntBitArray();

		for (int i = SIZE - 1; i >= 0; i--) {

			if (op2[i]) {
				result = result.plus(this.lshift(SIZE - 1 - i));
			}

		}

		return result;
	}

	// Computes this squared and returns it.
	public LargeIntBitArray square() {
		return this.multiply(this);
	}

	// Multiplies a long int with a regular int.
	public LargeIntBitArray multiply(int v) {
		return this.multiply(new LargeIntBitArray(v));
	}

	// Shifts this left by margin and returns the result
	public LargeIntBitArray lshift(int margin) {
		boolean[] result = new boolean[SIZE];

		for (int i = 0; i < SIZE; i++) {
			if (i + margin < SIZE)
				result[i] = value[i + margin];
			else
				result[i] = false;
		}

		return new LargeIntBitArray(result);
	}

	// Shifts this right by margin and returns the result
	public LargeIntBitArray rshift(int margin) {
		boolean[] result = new boolean[SIZE];

		for (int i = SIZE - 1; i >= 0; i--) {
			if (i >= margin)
				result[i] = value[i - margin];
			else
				result[i] = false;
		}

		return new LargeIntBitArray(result);
	}

	// returns TRUE if this is less than v.
	public boolean lessThan(LargeIntBitArray v) {
		boolean[] op2 = v.getValue();

		for (int i = 0; i < SIZE; i++) {
			if (!value[i] && op2[i])
				return true;
		}

		return false;
	}

	public String toString() {
		char[] string = new char[SIZE];
		for (int i = 0; i < SIZE; i++) {
			if (value[i] == true)
				string[i] = '1';
			else
				string[i] = '0';
		}
		String s = new String(string);
		return s;
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
