package cardmanager;

import com.licel.jcardsim.io.CAD;
import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;

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
