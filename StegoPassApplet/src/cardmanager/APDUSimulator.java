package cardmanager;

import stegopassapplet.StegoPassApplet;
import java.util.Random;

/**
 *
 * @author Martin Bajanik
 */
public class APDUSimulator {

    static CardMngr cardManager = new CardMngr();
    static short additionalDataLen = 4;

    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
        (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

    public static void main(String[] args) {
        try {
            byte[] installData = new byte[0];
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, StegoPassApplet.class);
            GetPassword(); // 6680
            GenerateNewPassword(); // 6680
            ChangePIN(); // 6680
            ResetPIN(true); // 6986
            
            SendPIN(false); // 6900
            SendPIN(false); // 6900
            SendPIN(false); // 6680

            ResetPIN(false); // 6900
            ResetPIN(false); // 6900
            // ResetPIN(false); // 6999 - Blocks applet.
            ResetPIN(true); // 9000
            
            SendPIN(true); // 9000
            
            ChangePIN(); // 9000
            SendPIN(true); // 6900
            SendPIN(false); // 9000
            
            GetPassword(); // 9000
            GenerateNewPassword(); // 9000
            GetPassword(); // 9000

        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    private static void SendPIN(boolean correct) throws Exception {
        byte pinApdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        pinApdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        pinApdu[CardMngr.OFFSET_INS] = (byte) 0x50;
        pinApdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
        if (!correct) {
            pinApdu[5] = (byte) 0x01;
            pinApdu[6] = (byte) 0x01;
            pinApdu[7] = (byte) 0x01;
            pinApdu[8] = (byte) 0x01;
        }
        cardManager.sendAPDUSimulator(pinApdu);
    }
    
    private static void ChangePIN() throws Exception {
        byte pinApdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        pinApdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        pinApdu[CardMngr.OFFSET_INS] = (byte) 0x51;
        pinApdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;
        pinApdu[5] = (byte) 0x01;
        pinApdu[6] = (byte) 0x01;
        pinApdu[7] = (byte) 0x01;
        pinApdu[8] = (byte) 0x01;
        
        cardManager.sendAPDUSimulator(pinApdu);
    }

    private static void ResetPIN(boolean correct) throws Exception {
        byte pinApdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        pinApdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        pinApdu[CardMngr.OFFSET_INS] = (byte) 0x52;
        pinApdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        pinApdu[CardMngr.OFFSET_LC] = (byte) 12;
        if (!correct) {
            pinApdu[5] = (byte) 0x01;
        }
        cardManager.sendAPDUSimulator(pinApdu);
    }

    private static void GetPassword() throws Exception {
        byte dataApdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        dataApdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        dataApdu[CardMngr.OFFSET_INS] = (byte) 0x53;
        dataApdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        dataApdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        dataApdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

        cardManager.sendAPDUSimulator(dataApdu);
    }
    
    private static void GenerateNewPassword() throws Exception {
        byte dataApdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        dataApdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        dataApdu[CardMngr.OFFSET_INS] = (byte) 0x54;
        dataApdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        dataApdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        dataApdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

        cardManager.sendAPDUSimulator(dataApdu);
    }
}
