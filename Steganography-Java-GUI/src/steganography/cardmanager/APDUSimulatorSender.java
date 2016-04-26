package steganography.cardmanager;

import java.util.Base64;
import stegopassapplet.StegoPassApplet;

/**
 *
 * @author Martin Bajanik
 */
public class APDUSimulatorSender {
    static CardMngr cardManager = new CardMngr();

    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};
    
    private final static byte[] ADMIN_PIN                 = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    private final static byte   ADMIN_PIN_LENGTH          = 0x0C;
    private final static byte   ADMIN_PIN_START           = 0x04;
    private final static byte[] DEFAULT_USER_PIN          = {0x00, 0x00, 0x00, 0x00};
    private final static byte   DEFAULT_USER_PIN_LENGTH   = 0x04;
    private final static byte   DEFAULT_USER_PIN_START    = 0x04 + ADMIN_PIN_LENGTH;
    
    public static void Initialize() {
        try {   
            // InstalData:
            // ADMIN_PIN_START | ADMIN_PIN_LENGTH | DEFAULT_USER_PIN_START | DEFAULT_USER_PIN_LENGTH | ADMIN_PIN | DEFAULT_USER_PIN 
            byte[] installData = new byte[255];
            installData[0] = ADMIN_PIN_START;
            installData[1] = ADMIN_PIN_LENGTH;
            installData[2] = DEFAULT_USER_PIN_START;
            installData[3] = DEFAULT_USER_PIN_LENGTH;
            
            System.arraycopy(ADMIN_PIN, 0, installData, ADMIN_PIN_START, ADMIN_PIN_LENGTH);
            System.arraycopy(DEFAULT_USER_PIN, 0, installData, DEFAULT_USER_PIN_START, DEFAULT_USER_PIN_LENGTH);
            
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, StegoPassApplet.class);           
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public static ResponseStatus SendPIN(String pin) throws Exception {     
        byte[] pinBytes = numericStringToHex(pin);
        byte[] pinApdu = prepareAPDU((byte) 0x50, pinBytes.length);
                     
        System.arraycopy(pinBytes, 0, pinApdu, 5, pinBytes.length);
       
        byte[] response = cardManager.sendAPDUSimulator(pinApdu);
        
        return ResponseStatus.getResponseStatus(response[0], response[1]);
    }
    
    public static ResponseStatus ChangePIN(String pin) throws Exception {
        byte[] pinBytes = numericStringToHex(pin);
        byte[] pinApdu = prepareAPDU((byte) 0x51, pinBytes.length);
                     
        System.arraycopy(pinBytes, 0, pinApdu, 5, pinBytes.length);
       
        byte[] response = cardManager.sendAPDUSimulator(pinApdu);
        
        return ResponseStatus.getResponseStatus(response[0], response[1]);
    }
    
    public static ResponseStatus RegeneratePassword() throws Exception {
        byte[] apdu = prepareAPDU((byte) 0x54, 0);
        
        byte[] response = cardManager.sendAPDUSimulator(apdu);      
        return ResponseStatus.getResponseStatus(response[0], response[1]);    
    }
    
    public static String getPassword() throws Exception {
        byte[] apdu = prepareAPDU((byte) 0x53, 0);
        byte[] result = new byte[24];
        byte[] response = cardManager.sendAPDUSimulator(apdu); 
        
        if (ResponseStatus.getResponseStatus(response[response.length - 2], response[response.length -1]) == ResponseStatus.SW_OK) {
            System.arraycopy(response, 0, result, 0, 24);
            return Base64.getEncoder().encodeToString(result); 
        }
        
        return null;
    }
    
    private static byte[] prepareAPDU(byte instruction, int additionalDataLength){
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

        for(int i = 0; i < pinBytes.length; ++i) {
            pinBytes[i] = (byte)Integer.parseInt(String.valueOf(pin.charAt(i)));
        }
        
        return pinBytes;
    }
}
