import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Assignment1 {
    public static void main(String[] args) {

        String inputFile = args[0];

        //BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);
        BigInteger b = new BigInteger("56a7252dfe29400642443fa4aec8c350af275094552e9734b93520c96950470f785cfef2aefac6cfacbf3ff10139d8cf85e51a74c3e1eee924bbdcfe506f47d8c8d18b3b5f17bf6cffa60efa7ee135cb7772f6a2bcdc153a7bd2b4b928ebafeab67cec4a8ecf00f15336cae3e14bef8a2f6783890d41bc84cb32b1c6fcc59d02", 16);
        BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);
        BigInteger A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);
        
        //BigInteger B = new BigInteger(squareAndMultiply(g, b, p).toString(16), 16);

        BigInteger s = new BigInteger(squareAndMultiply(A, b, p).toString(16), 16);
        byte[] sBytes = s.toByteArray();
        
        byte[] digest = null;

        // Generate SHA256 digest giving AES key
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            digest = sha256.digest(sBytes);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("No such algorithm exception");
        }

        SecretKeySpec k = new SecretKeySpec(digest, "AES");

        String iv = "b3de17f3e53ee943ba45731ba1e1d888"; // Pre-generated IV
        byte[] ivBytes = new BigInteger(iv, 16).toByteArray();
        ivBytes = Arrays.copyOfRange(ivBytes, 1, ivBytes.length); // Trim leading zero byte

        // Generate and initiate cipher with AES key and IV and encrypt file
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, k, ivSpec);

            byte[] encryptedData = encryptMessage(inputFile, cipher);
            System.out.println(bytesToHexString(encryptedData));

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.err.println("No such algorithm or padding exception triggered");
        } catch (InvalidKeyException e) {
            System.err.println("Invalid AES key exception");
        } catch (InvalidAlgorithmParameterException e) {
            System.err.println("Invalid IV exception");
        }
    }

    // Right to left square and multiply function
    public static BigInteger squareAndMultiply(BigInteger g, BigInteger x, BigInteger p) {
        BigInteger y = BigInteger.ONE;

        String binary = x.toString(2);
        for (int i = 0; i < binary.length(); i++) {

            if (binary.charAt(i) == '1') {
                y = (y.multiply(g)).mod(p);
            }

            g = (g.multiply(g)).mod(p);
        }
        return y;
    }

    public static byte[] padFile(byte[] data) {
        int paddingLength = 16 - (data.length % 16); // Get number of bytes needed for padding
        
        byte[] paddedData;
        if (paddingLength == 0) { // If the end of message is a multiple of the block size 16
            paddedData = new byte[data.length + 16];
            System.arraycopy(data, 0, paddedData, 0, data.length);
            paddedData[data.length] = (byte) 0x80;
        } else { //If the end of message is less than the block size 16
            paddedData = new byte[data.length + paddingLength];
            System.arraycopy(data, 0, paddedData, 0, data.length);
            paddedData[data.length] = (byte) 0x80;
        }
        return paddedData;
    }

    // Encryption function
    public static byte[] encryptMessage(String inputFile, Cipher cipher) {
        byte[] data = new byte[0];
        byte[] encryptedData = new byte[0];

        try (FileInputStream is = new FileInputStream(inputFile)) {
            data = is.readAllBytes();
            byte[] paddedData = padFile(data); // Apply padding to file
            encryptedData = cipher.doFinal(paddedData); // Encrypt file with the cipher
        } catch (FileNotFoundException e){
            System.err.println("File not found exception");
        } catch (IOException e) {
            System.err.println("IO exception");
        } catch (IllegalBlockSizeException e) {
            System.err.println("Illegal block size exception");
        } catch (BadPaddingException e) {
            System.err.println("Bad padding exception");
        }

        return encryptedData;
    }

    // Convert byte array to a hexstring
    public static String bytesToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(); // Initialise a stringbuilder to build the hex string
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b)); // Append hex value to stringbuilder
        }
        return hexString.toString(); // Return stringbuilder as a string
    }
    
}