package lyn.util.cipher;

import java.security.Key;

public interface Operation {
    public byte[] encrypt(byte[] plain, Object key);

    public byte[] decrypt(byte[] cipher, Object key);
}
