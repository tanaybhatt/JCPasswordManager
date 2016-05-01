package steganography.keystoremanager;

import java.security.Key;
import java.security.KeyStore;
import java.util.Scanner;

/**
 *
 * @author Martin Bajanik
 */
public class KeyExtractor {
    public static void main(String args[]) throws Exception  {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("Enter PIN:");
        String password = scanner.nextLine();
        
        KeyStore ks = KeyStore.getInstance("JCEKS");
        String pass = "KS" + password;
        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream("store.ks");
            ks.load(fis, pass.toCharArray());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }

        Key key = ks.getKey("SecureChannelPSK", pass.toCharArray());
        System.out.println(bytesToHex(key.getEncoded()));
    }
    
    private static String bytesToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            buf.append(byteToHex(data[i]));
            buf.append("");
        }
        return (buf.toString().toUpperCase());
    }

    private static String byteToHex(byte data) {
        StringBuilder buf = new StringBuilder();
        buf.append(toHexChar((data >>> 4) & 0x0F));
        buf.append(toHexChar(data & 0x0F));
        return buf.toString();
    }

    private static char toHexChar(int i) {
        if ((0 <= i) && (i <= 9)) {
            return (char) ('0' + i);
        } else {
            return (char) ('a' + (i - 10));
        }
    }
}
