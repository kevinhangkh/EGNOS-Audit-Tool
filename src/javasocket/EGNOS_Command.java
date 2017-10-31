/***************************************************************************
 * Copyright : Thales Alenia Space
 * Project: EGNOS
 * File: EGNOS_Command.java
 * Date: 20/05/2016
 * Purpose : EGNOS command
 * Language : Java
 * Author : Kevin HANG
 * History :
 *
 * Version | Date | Name | Change History
 * 01.00 | 20/05/16 | KH | First Creation
 *.
 ***************************************************************************/
package javasocket;

/*****************************************************************************
 * Class Name : EGNOS_Command
 * Purpose : Contains the Command section of an EGNOS message.
 * *************************************************************************/
public final class EGNOS_Command {
    
    byte sectionIdentifier;
    byte[] sectionLength = new byte[2];
    byte[] confirmationKey = new byte[20];
    byte commandID; // never changes
    byte commandType;
    byte[] commandParameter = new byte[2];
    int sLen;
    boolean isItRegularCmd = false;
    
    public EGNOS_Command(byte sId, byte [] confirmKey, byte cmdType, byte[] cmdParam) {
        sectionIdentifier = sId;
        sectionLength = new byte[] {(byte) 0x00,(byte) computeSectionLength()};
        confirmationKey = confirmKey;
        commandID = 0x00;
        commandType = cmdType;
        commandParameter = new byte [cmdParam.length];
        commandParameter = cmdParam;
        isItRegularCmd = true;
    }
    
    /*****************************************************************************
     * Name : computeSectionLength
     * Purpose : Compute the length of this section
     * Argument I/O: 
     * I/O Files: No input file
     * Returns : length of the section
     *
     * @return  *************************************************************************/
    public int computeSectionLength() {
        int sIdLen = 1, cIdLen = 1, cTypeLen = 1, cParamLen = 1;
        
        sLen = sIdLen + this.sectionLength.length + this.confirmationKey.length + cIdLen + cTypeLen + this.commandParameter.length;
        
        return sLen;
    }
    
    /*****************************************************************************
     * Name : printCmd
     * Purpose : Print the Command section of an EGNOS message
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     *  *************************************************************************/
    public void printCmd() {
        System.out.println();
        System.out.println("***COMMAND***");
        System.out.println();
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
        System.out.printf("commandParameter :");
        for (int i=0;i<this.commandParameter.length;i++)
        {
            System.out.printf("%02X ",this.commandParameter[i]);
        }
        System.out.println("\n");
    }
}
