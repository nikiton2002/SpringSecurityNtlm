package com.example.demo.ntlm;

public class BigEndianCodec {

	static double getDouble(byte[] bytes, int index) {
		return Double.longBitsToDouble(getLong(bytes, index));
	}

	static float getFloat(byte[] bytes, int index) {
		return Float.intBitsToFloat(getInt(bytes, index));
	}

	public static int getInt(byte[] bytes, int index) {
		return (bytes[index] << 24) + ((bytes[index + 1] & 0xFF) << 16) +
			((bytes[index + 2] & 0xFF) << 8) + (bytes[index + 3] & 0xFF);
	}

	public static long getLong(byte[] bytes, int index) {
		return (((long)bytes[index]) << 56) +
			((bytes[index + 1] & 0xFFL) << 48) +
			((bytes[index + 2] & 0xFFL) << 40) +
			((bytes[index + 3] & 0xFFL) << 32) +
			((bytes[index + 4] & 0xFFL) << 24) +
			((bytes[index + 5] & 0xFFL) << 16) +
			((bytes[index + 6] & 0xFFL) << 8) +
			(bytes[index + 7] & 0xFFL);
	}

	public static void putInt(byte[] bytes, int index, int i) {
		bytes[index] = (byte)(i >>> 24);
		bytes[index + 1] = (byte)(i >>> 16);
		bytes[index + 2] = (byte)(i >>> 8);
		bytes[index + 3] = (byte)i;
	}

	public static void putLong(byte[] bytes, int index, long l) {
		bytes[index] = (byte)(l >>> 56);
		bytes[index + 1] = (byte)(l >>> 48);
		bytes[index + 2] = (byte)(l >>> 40);
		bytes[index + 3] = (byte)(l >>> 32);
		bytes[index + 4] = (byte)(l >>> 24);
		bytes[index + 5] = (byte)(l >>> 16);
		bytes[index + 6] = (byte)(l >>> 8);
		bytes[index + 7] = (byte)l;
	}

}