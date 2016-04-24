package cardmanager;

import stegopassapplet.StegoPassApplet;

/**
 *
 * @author Martin Bajanik
 */
public class APDUSender {

    static CardMngr cardManager = new CardMngr();
    static short additionalDataLen = 4;

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
        
        byte pinApdu[] = new byte[CardMngr.HEADER_LENGTH + pinBytes.length];
        pinApdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        pinApdu[CardMngr.OFFSET_INS] = (byte) 0x50;
        pinApdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_LC] = (byte) pinBytes.length;
                     
        System.arraycopy(pinBytes, 0, pinApdu, 5, pinBytes.length);
       
        byte[] response = cardManager.sendAPDUSimulator(pinApdu);
        
        return ResponseStatus.getResponseStatus(response[0], response[1]);
    }

    private static byte[] numericStringToHex(String pin) {
        byte[] pinBytes = new byte[pin.length()];

        for(int i = 0; i < pinBytes.length; ++i) {
            pinBytes[i] = (byte)Integer.parseInt(String.valueOf(pin.charAt(i)));
        }
        
        return pinBytes;
    }
}
