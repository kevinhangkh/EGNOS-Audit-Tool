/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package javasocket;

/**
 *
 * @author admin
 */
public class EGNOS_Command_CCF {
    byte sectionIdentifier;
    byte[] sectionLength = new byte[2];
    byte[] confirmationKey = new byte[20];
    byte commandID; // never changes
    byte commandType;
    byte commandParameter;
    int sLen;
    boolean isItCCFCmd = false;
    
    public EGNOS_Command_CCF(byte sId, byte [] confirmKey, byte cmdType, byte cmdParam) {
        sectionIdentifier = sId;
        sectionLength = new byte[] {(byte) 0x00,(byte) computeSectionLength()};
        confirmationKey = confirmKey;
        commandID = 0x00;
        commandType = cmdType;
        commandParameter = cmdParam;
        isItCCFCmd = true;
    }
    
    public int computeSectionLength() {
        int sIdLen = 1, cIdLen = 1, cTypeLen = 1, cParamLen = 1;
        
        sLen = sIdLen + this.sectionLength.length + this.confirmationKey.length + cIdLen + cTypeLen + cParamLen;
        
        return sLen;
    }
    
    public void printCmd() {
        System.out.println("***COMMAND***");
        System.out.printf("sectionID = %02X \n",this.sectionIdentifier);
        System.out.printf("sectionLength :");
        for (int i=0;i<this.sectionLength.length;i++)
        {
            System.out.printf("%02X ",this.sectionLength[i]);
        }
        System.out.println("");
        System.out.printf("confirmationKey :");
        for (int i=0;i<this.confirmationKey.length;i++)
        {
            System.out.printf("%02X ",this.confirmationKey[i]);
        }
        System.out.println("");
        System.out.printf("commandID = %02X \n",this.commandID);
        System.out.printf("commandType = %02X \n",this.commandType);
        System.out.printf("commandParameter = %02X \n",this.commandParameter);
    }
}
