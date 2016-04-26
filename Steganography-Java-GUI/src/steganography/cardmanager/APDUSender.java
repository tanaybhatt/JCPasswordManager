package steganography.cardmanager;

import java.util.Base64;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author Martin Bajanik
 */
public class APDUSender {

    static CardMngr cardManager = new CardMngr();

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
        byte[] result;
        
        ResponseAPDU resp = cardManager.sendAPDU(apdu);
        int response = resp.getSW();    

        if (ResponseStatus.getResponseStatus(response) == ResponseStatus.SW_OK) {
            byte temp[] = resp.getBytes();
            result = new byte[temp.length];
            System.arraycopy(temp, 0, result, 0, temp.length - 2);
            return Base64.getEncoder().encodeToString(result);
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
}
