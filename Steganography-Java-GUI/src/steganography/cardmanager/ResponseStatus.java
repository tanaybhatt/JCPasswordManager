package steganography.cardmanager;

/**
 *
 * @author Martin Bajanik
 */
public enum ResponseStatus {
    SW_OK ((byte) 0x90, (byte) 0x00, 0x9000),
    SW_BAD_PIN ((byte) 0x69,(byte) 0x00, 0x6900),
    SW_SECURITY_STATUS_NOT_SATISFIED ((byte) 0x66, (byte) 0x80, 0x6680),
    SW_APPLET_BLOCKED ((byte) 0x69, (byte) 0x99, 0x6999),
    SW_UNKNOWN ((byte) 0xFF,(byte) 0xFF, 0xFFFF);

    private final byte first;
    private final byte second;
    private final int value;

    ResponseStatus(byte first, byte second, int value) {
        this.first = first;
        this.second = second;
        this.value = value;
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
    
    public static ResponseStatus getResponseStatus(int value){
        switch (value) {
            case (0x9000): return SW_OK;
            case (0x6900): return SW_BAD_PIN;
            case (0x6680): return SW_SECURITY_STATUS_NOT_SATISFIED;
            case (0x6999): return SW_APPLET_BLOCKED;
            default: return SW_UNKNOWN;
        }
    }
    
    @Override
    public String toString()
    {
       return String.format("%d%d (%d)", this.first, this.second, this.value);
    }
}
