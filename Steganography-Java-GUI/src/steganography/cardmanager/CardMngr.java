package steganography.cardmanager;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import java.util.List;
import javacard.framework.AID;
import javax.smartcardio.ATR;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

public class CardMngr {

    CardTerminal m_terminal = null;
    CardChannel m_channel = null;
    Card m_card = null;

    // Simulator related attributes
    private static CAD m_cad = null;
    private static JavaxSmartCardInterface m_simulator = null;

    public static final byte OFFSET_CLA = 0x00;
    public static final byte OFFSET_INS = 0x01;
    public static final byte OFFSET_P1 = 0x02;
    public static final byte OFFSET_P2 = 0x03;
    public static final byte OFFSET_LC = 0x04;
    public static final byte OFFSET_DATA = 0x05;
    public static final byte HEADER_LENGTH = 0x05;
       
    public boolean ConnectToCard() throws Exception {
        List terminalList = GetReaderList();

        if (terminalList.isEmpty()) {
            System.out.println("No terminals found.");
        }

        //List numbers of Card readers
        boolean cardFound = false;
        for (int i = 0; i < terminalList.size(); i++) {
            System.out.println(i + " : " + terminalList.get(i));
            m_terminal = (CardTerminal) terminalList.get(i);
            if (m_terminal.isCardPresent()) {
                m_card = m_terminal.connect("*");
                System.out.println("card: " + m_card);
                m_channel = m_card.getBasicChannel();

                //reset the card
                ATR atr = m_card.getATR();
                System.out.println(bytesToHex(m_card.getATR().getBytes()));
                
                cardFound = true;
            }
        }

        return cardFound;
    }
    
    public void DisconnectFromCard() throws Exception {
        if (m_card != null) {
            m_card.disconnect(false);
            m_card = null;
        }
    }
    
    public List GetReaderList() {
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List readersList = factory.terminals().list();
            return readersList;
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
            return null;
        }
    }
    
    public ResponseAPDU sendAPDU(byte apdu[]) throws Exception {
        CommandAPDU commandAPDU = new CommandAPDU(apdu);

        System.out.println(">>>>");
        System.out.println(commandAPDU);

        System.out.println(bytesToHex(commandAPDU.getBytes()));

        ResponseAPDU responseAPDU = m_channel.transmit(commandAPDU);

        System.out.println(responseAPDU);
        System.out.println(bytesToHex(responseAPDU.getBytes()));

        if (responseAPDU.getSW1() == (byte) 0x61) {
            CommandAPDU apduToSend = new CommandAPDU((byte) 0x00,
                    (byte) 0xC0, (byte) 0x00, (byte) 0x00,
                    (int) responseAPDU.getSW1());

            responseAPDU = m_channel.transmit(apduToSend);
            System.out.println(bytesToHex(responseAPDU.getBytes()));
        }

        System.out.println("<<<<");

        return (responseAPDU);
    }

    public boolean prepareLocalSimulatorApplet(byte[] appletAIDArray, byte[] installData, Class appletClass) {
        System.setProperty("com.licel.jcardsim.terminal.type", "2");
        m_cad = new CAD(System.getProperties());
        m_simulator = (JavaxSmartCardInterface) m_cad.getCardInterface();
        AID appletAID = new AID(appletAIDArray, (short) 0, (byte) appletAIDArray.length);

        AID appletAIDRes = m_simulator.installApplet(appletAID, appletClass, installData, (short) 0, (byte) installData.length);
        return m_simulator.selectApplet(appletAID);

    }

    public byte[] sendAPDUSimulator(byte apdu[]) throws Exception {
        System.out.println(">>>>");
        System.out.println(bytesToHex(apdu));

        byte[] responseBytes = m_simulator.transmitCommand(apdu);

        System.out.println(bytesToHex(responseBytes));
        System.out.println("<<<<");

        return responseBytes;
    }

    private String bytesToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            buf.append(byteToHex(data[i]));
            buf.append(" ");
        }
        return (buf.toString());
    }

    private String byteToHex(byte data) {
        StringBuilder buf = new StringBuilder();
        buf.append(toHexChar((data >>> 4) & 0x0F));
        buf.append(toHexChar(data & 0x0F));
        return buf.toString();
    }

    private char toHexChar(int i) {
        if ((0 <= i) && (i <= 9)) {
            return (char) ('0' + i);
        } else {
            return (char) ('a' + (i - 10));
        }
    }
}
