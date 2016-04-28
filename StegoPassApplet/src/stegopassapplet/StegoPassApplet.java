package stegopassapplet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;

/**
 *
 * @author Martin Bajanik
 */
public class StegoPassApplet extends javacard.framework.Applet {
    final static byte CLA_STEGOPASSAPPLET = (byte) 0xB0;
    final static byte INS_VERIFY = (byte) 0x50;
    final static byte INS_CHANGEPIN = (byte) 0x51;
    final static byte INS_RESETPIN = (byte) 0x52;
    final static byte INS_GETPASSWORD = (byte) 0x53;
    final static byte INS_GENNEWPASSWORD = (byte) 0x54;

    private OwnerPIN m_admin_pin = null;
    private OwnerPIN m_user_pin = null;
    private DESKey m_password = null;
    private RandomData m_secureRandom = null;
    private byte m_ramArray[] = null;

    final static byte RANDOM_DATA_SIZE = (byte) 0x1E;
    final static short ARRAY_LENGTH = (short) 0xff;

    final static short SW_BAD_PIN = (short) 0x6900;
    final static short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6680;
    final static short SW_APPLET_BLOCKED = (short) 0x6999;

    private boolean appletBlocked = false;

    protected StegoPassApplet(byte[] buffer, short offset, byte length) {
        short dataOffset = offset;
        dataOffset += (short) (1 + buffer[offset]);
        dataOffset += (short) (1 + buffer[dataOffset]);

        if (buffer[dataOffset] != 0x12) {
            ISOException.throwIt((short) (ISO7816.SW_WRONG_LENGTH + offset + length - dataOffset));
        }
        dataOffset++;

        byte adminPinLength = buffer[dataOffset];
        byte userPinLength = buffer[(short) (dataOffset + 1)];

        dataOffset += 2;

        m_admin_pin = new OwnerPIN((byte) 3, adminPinLength);
        m_admin_pin.update(buffer, dataOffset, adminPinLength);

        dataOffset += adminPinLength;

        m_user_pin = new OwnerPIN((byte) 3, userPinLength);
        m_user_pin.update(buffer, dataOffset, userPinLength);

        /* THIS IS USED WITH SIMULATOR. UNCOMMENT IF NEEDED AND COMMENT CODE ABOVE.
        
        m_admin_pin = new OwnerPIN((byte) 3, buffer[offset + (byte) 1]);
        m_admin_pin.update(buffer, buffer[offset], buffer[offset + (byte) 1]);

        m_user_pin = new OwnerPIN((byte) 3, buffer[offset + (byte) 3]);
        m_user_pin.update(buffer, buffer[offset + (byte) 2], buffer[offset + (byte) 3]);*/
        
        m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
        m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        m_password = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
        byte[] randomBytes = new byte[RANDOM_DATA_SIZE];
        generateSeed(randomBytes, RANDOM_DATA_SIZE);
        m_password.setKey(randomBytes, (byte) 0);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new StegoPassApplet(bArray, bOffset, bLength).register();
    }

    public boolean select() {
        m_user_pin.reset();
        return true;
    }

    public void process(APDU apdu) throws ISOException {
        byte[] apduBuffer = apdu.getBuffer();

        if (appletBlocked) {
            ISOException.throwIt(SW_APPLET_BLOCKED);
        }

        if (selectingApplet()) {
            return;
        }

        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_STEGOPASSAPPLET) {
            switch (apduBuffer[ISO7816.OFFSET_INS]) {
                case INS_CHANGEPIN:
                    ChangePIN(apdu);
                    break;
                case INS_VERIFY:
                    VerifyPIN(apdu);
                    break;
                case INS_RESETPIN:
                    ResetPIN(apdu);
                    break;
                case INS_GETPASSWORD:
                    GetPassword(apdu);
                    break;
                case INS_GENNEWPASSWORD:
                    GenerateNewPassword(apdu);
                    break;
                default:
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                    break;
            }
        } else {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
    }

    private void VerifyPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (m_user_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false) {
            if (m_user_pin.getTriesRemaining() <= (byte) 0) {
                // PIN IS NOW BLOCKED
                ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            ISOException.throwIt(SW_BAD_PIN);
        }
    }

    private void ChangePIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (!m_user_pin.isValidated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        m_user_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
        m_user_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
    }

    private void ResetPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // RESET PIN NOT AVAILABLE
        if (m_user_pin.getTriesRemaining() > (byte) 0) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }

        if (m_admin_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false) {
            if (m_admin_pin.getTriesRemaining() <= (byte) 0) {
                // APPLET IS NOW BLOCKED
                appletBlocked = true;
                ISOException.throwIt(SW_APPLET_BLOCKED);
            }
            ISOException.throwIt(SW_BAD_PIN);
        }

        byte[] resetPIN = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        m_user_pin.update(resetPIN, (byte) 0, (byte) 4);
        m_user_pin.resetAndUnblock();
    }

    private void GetPassword(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        if (!m_user_pin.isValidated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short keyLength = m_password.getKey(m_ramArray, (byte) 0);
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, keyLength);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, keyLength);
    }

    private void GenerateNewPassword(APDU apdu) {
        if (!m_user_pin.isValidated()) {
            ISOException.throwIt(SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        byte[] randomBytes = new byte[RANDOM_DATA_SIZE];
        generateSeed(randomBytes, RANDOM_DATA_SIZE);
        m_password.setKey(randomBytes, (byte) 0);
    }

    private void generateSeed(byte[] randomBytes, byte dataSize) {
        m_secureRandom.generateData(randomBytes, (byte) 0, dataSize);
    }
}
