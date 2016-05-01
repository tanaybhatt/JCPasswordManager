package steganography.cardmanager;

import java.security.Key;
import java.security.KeyStore;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Martin Bajanik
 */
public class APDUSender {

    static CardMngr cardManager = new CardMngr();
    private static String actualPIN;
    private static Key secureChannelPSK;

    public static void Initialize() throws Exception {
        try {
            if (!cardManager.ConnectToCard()) {
                throw new Exception("Failed to connect to card");
            }
        } catch (Exception ex) {
            throw ex;
        }
    }

    public static void Release() throws Exception {
        cardManager.DisconnectFromCard();
    }

    public static ResponseStatus SendPIN(String pin) throws Exception {
        byte[] pinBytes = numericStringToHex(pin);
        byte[] pinApdu = prepareAPDU((byte) 0x50, pinBytes.length);

        System.arraycopy(pinBytes, 0, pinApdu, 5, pinBytes.length);

        ResponseAPDU resp = cardManager.sendAPDU(pinApdu);
        int response = resp.getSW();

        return ResponseStatus.getResponseStatus(response);
    }

    public static ResponseStatus ChangePIN(String pin) throws Exception {
        byte[] pinBytes = numericStringToHex(pin);
        byte[] pinApdu = prepareAPDU((byte) 0x51, pinBytes.length);

        System.arraycopy(pinBytes, 0, pinApdu, 5, pinBytes.length);

        ResponseAPDU resp = cardManager.sendAPDU(pinApdu);
        int response = resp.getSW();

        return ResponseStatus.getResponseStatus(response);
    }

    public static ResponseStatus RegeneratePassword() throws Exception {
        byte[] apdu = prepareAPDU((byte) 0x54, 0);

        ResponseAPDU resp = cardManager.sendAPDU(apdu);
        int response = resp.getSW();

        return ResponseStatus.getResponseStatus(response);
    }

    public static String getPassword() throws Exception {
        byte[] apdu = prepareAPDU((byte) 0x53, 0);
        byte[] encrypted;

        ResponseAPDU resp = cardManager.sendAPDU(apdu);
        int response = resp.getSW();

        if (ResponseStatus.getResponseStatus(response) == ResponseStatus.SW_OK) {
            byte[] temp = resp.getBytes();
            encrypted = new byte[temp.length - 2];
            System.arraycopy(temp, 0, encrypted, 0, temp.length - 2);
            
            byte[] iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher aesCipher = Cipher.getInstance("AES/CBC/NoPadding");
            aesCipher.init(Cipher.DECRYPT_MODE, APDUSender.secureChannelPSK, ivSpec);

            byte[] plaintextKey = new byte[16];
            aesCipher.doFinal(encrypted, 0, encrypted.length, plaintextKey, 0);
            return Base64.getEncoder().encodeToString(plaintextKey);
        }

        return null;
    }

    private static byte[] prepareAPDU(byte instruction, int additionalDataLength) {
        byte pinApdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLength];
        pinApdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        pinApdu[CardMngr.OFFSET_INS] = (byte) instruction;
        pinApdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_LC] = (byte) additionalDataLength;

        return pinApdu;
    }

    private static byte[] numericStringToHex(String pin) {
        byte[] pinBytes = new byte[pin.length()];

        for (int i = 0; i < pinBytes.length; ++i) {
            pinBytes[i] = (byte) Integer.parseInt(String.valueOf(pin.charAt(i)));
        }

        return pinBytes;
    }

    public static void initializeSecretChannelKey(String password) throws Exception {
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

        secureChannelPSK = ks.getKey("SecureChannelPSK", pass.toCharArray());
        actualPIN = password;
    }    
    
    public static void changeKeyStorePassword(String newPassword) throws Exception {
        KeyStore ks = KeyStore.getInstance("JCEKS");
        String oldPass = "KS" + actualPIN;
        String newPass = "KS" + newPassword;
        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream("store.ks");
            ks.load(fis, oldPass.toCharArray());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream("store.ks");
            ks.store(fos, newPass.toCharArray());
        } finally {
            if (fis != null) {
                fis.close();
            }
        }
        
        actualPIN = newPassword;
    }
}
