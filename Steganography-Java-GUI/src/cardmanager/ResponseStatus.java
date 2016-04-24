package cardmanager;

/**
 *
 * @author Martin Bajanik
 */
public enum ResponseStatus {
    SW_OK ((byte) 0x90, (byte) 0x00),
    SW_BAD_PIN ((byte) 0x69,(byte) 0x00),
    SW_SECURITY_STATUS_NOT_SATISFIED ((byte) 0x66, (byte) 0x80),
    SW_APPLET_BLOCKED ((byte) 0x69, (byte) 0x99),
    SW_UNKNOWN ((byte) 0xFF,(byte) 0xFF);

    private final byte first;
    private final byte second;

    ResponseStatus(byte first, byte second) {
        this.first = first;
        this.second = second;
    }
    
    public static ResponseStatus getResponseStatus(byte first, byte second){
        switch (first) {
            case (byte)0x90:
                if (second == (byte)0x00) return SW_OK;
                break;                
            case (byte)0x69:
                if (second == (byte)0x00) return SW_BAD_PIN;
                if (second == (byte)0x99) return SW_APPLET_BLOCKED;
                break;
                         
            case (byte)0x66:
                if (second == (byte)0x80) return SW_SECURITY_STATUS_NOT_SATISFIED;
                break;
                        
            default:
                break;
        }
        return SW_UNKNOWN;
    }
}
