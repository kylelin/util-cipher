package lyn.util.cipher.impl;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;

import lyn.util.cipher.Operation;
import lyn.util.cipher.paillier.Paillier;

public class HomomorphicOperation implements Operation {

    public byte[] encrypt(byte[] plain, Object key) {
        List<Integer> hints = (List<Integer>) key;
        int bitLengthVal = hints.get(0);
        int certainty = hints.get(1);

        Paillier paillier = new Paillier(bitLengthVal, certainty);
        return paillier.Encryption(BigInteger.valueOf((long) ByteBuffer.wrap(plain).getInt())).toByteArray();
    }

    public byte[] decrypt(byte[] cipher, Object key) {
        List<Integer> hints = (List<Integer>) key;
        int bitLengthVal = hints.get(0);
        int certainty = hints.get(1);

        Paillier paillier = new Paillier(bitLengthVal, certainty);
        return paillier.Decryption(BigInteger.valueOf((long) ByteBuffer.wrap(cipher).getInt())).toByteArray();
    }

}
