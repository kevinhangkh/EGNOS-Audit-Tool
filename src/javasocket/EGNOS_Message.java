/**
 * *************************************************************************
 * Copyright : Thales Alenia Space
 * Project: EGNOS
 * File: EGNOS_Message.java
 * Date: 20/05/2016
 * Purpose : EGNOS message including a header and a command
 * Language : Java
 * Author : Kevin HANG
 * History :
 *
 * Version | Date | Name | Change History
 * 01.00 | 20/05/16 | KH | First Creation
 *.
 **************************************************************************
 */
package javasocket;

import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

/*****************************************************************************
 * Class Name : EGNOS_Message
 * Purpose : Contains an EGNOS command.
 * *************************************************************************/
public class EGNOS_Message {

    String name;
    boolean CCFMsg = false;
    boolean CCFACK = false;
    boolean response = false;

    public EGNOS_StandardHeader EGNOS_Header;
    public EGNOS_Command EGNOS_Cmd;
    public EGNOS_Command_CCF EGNOS_Cmd_CCF;
    public EGNOS_Command_CCF_ACK EGNOS_Cmd_CCF_ACK;
    public EGNOS_Command_Response EGNOS_Cmd_Resp;
    public EGNOS_Command_Response_Requested_Data EGNOS_Cmd_Resp_Req_Data;
    public byte crcByte1;
    public byte crcByte2;
    public byte crcByte3;
    public byte crcByte4;
    public byte crcByte5;
    public byte crcByte6;
    public byte crcByte7;
    public byte crcByte8;
    public byte[] crcByteCombined1;

    public EGNOS_Message(String n, boolean isItCCF, boolean isItCCFACK, boolean isItResponse) throws FileNotFoundException {
        name = n;
        CCFMsg = isItCCF;
        CCFACK = isItCCFACK;
        response = isItResponse;
        
        System.out.println("Name of message is: " + name + " ; CCFMsg: " + CCFMsg + " ; CCFACK: " + CCFACK + " ; Response: " + response);
        
        if (!response) {
            resetStdOutput();
            System.out.println(name);
            setLog();
        }
        
    }

    /*****************************************************************************
     * Name : setLog
     * Purpose : Redirect the output to a log file
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     * 
     * @throws java.io.FileNotFoundException *************************************************************************/
    public final void setLog() throws FileNotFoundException {
        PrintStream out = new PrintStream(new FileOutputStream("log.txt",true));
        System.setOut(out);
    }
    
    /*****************************************************************************
     * Name : resetStdOutput
     * Purpose : Redirect the output to the standard output
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :.
     *  *************************************************************************/
    public final void resetStdOutput() {
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
}
    
    /*****************************************************************************
     * Name : computeDataLength
     * Purpose : Compute the length of the whole EGNOS message
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :.
     *  *************************************************************************/
    void computeDataLength() {
        int dataLength;

        if (CCFMsg) {
            dataLength = this.EGNOS_Header.hLen + this.EGNOS_Cmd_CCF.sLen;
        } 
        else if (CCFACK) {
            int cmdDataLength = 95;
            dataLength = this.EGNOS_Header.hLen + cmdDataLength;
        }
        else {
            dataLength = this.EGNOS_Header.hLen + this.EGNOS_Cmd.sLen;
        }
        this.EGNOS_Header.dataLength = new byte[]{(byte) 0x00, (byte) dataLength};
    }

    /**
     * ***************************************************************************
     * Name : concatenate 
     * Purpose : gather all parts of the message in one big byte array 
     * Argument I/O: all bytes that constitute the message 
     * I/O Files: No input file 
     * Returns : byte array containing the whole message.
     * ************************************************************************
     */
    byte[] concatenate() {

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try {
            output.write(this.EGNOS_Header.versionNum);
            output.write(this.EGNOS_Header.msgType);
            output.write(this.EGNOS_Header.flowType);
            output.write(this.EGNOS_Header.dataLength);
            output.write(this.EGNOS_Header.headerLength);
            output.write(this.EGNOS_Header.originAddress);
            output.write(this.EGNOS_Header.originPort);
            output.write(this.EGNOS_Header.destinationAddress);
            output.write(this.EGNOS_Header.destinationPort);
            output.write(this.EGNOS_Header.timeStamp);
            output.write(this.EGNOS_Header.spare);
            output.write(this.EGNOS_Header.originalDestinationAddress);
            output.write(this.EGNOS_Header.originalTime);
            output.write(this.EGNOS_Header.fullMessageCRC);
            if (CCFMsg) {
                System.out.println("CONCATENATE CCF MSG !!!");
                output.write(this.EGNOS_Cmd_CCF.sectionIdentifier);
                output.write(this.EGNOS_Cmd_CCF.sectionLength);
                output.write(this.EGNOS_Cmd_CCF.confirmationKey);
                output.write(this.EGNOS_Cmd_CCF.commandID);
                output.write(this.EGNOS_Cmd_CCF.commandType);
                output.write(this.EGNOS_Cmd_CCF.commandParameter);
            } 
            else if (CCFACK) {
                System.out.println("CONCATENATE CCF ACK MSG !!!");
                output.write(this.EGNOS_Cmd_CCF_ACK.sectionIdentifier);
                output.write(this.EGNOS_Cmd_CCF_ACK.sectionLength);
                output.write(this.EGNOS_Cmd_CCF_ACK.confirmationKey);
                output.write(this.EGNOS_Cmd_CCF_ACK.commandID);
                output.write(this.EGNOS_Cmd_CCF_ACK.commandType);
                output.write(this.EGNOS_Cmd_CCF_ACK.commandParameter);
            }
            else {
                output.write(this.EGNOS_Cmd.sectionIdentifier);
                output.write(this.EGNOS_Cmd.sectionLength);
                output.write(this.EGNOS_Cmd.confirmationKey);
                output.write(this.EGNOS_Cmd.commandID);
                output.write(this.EGNOS_Cmd.commandType);
                output.write(this.EGNOS_Cmd.commandParameter);
            }

        } catch (Exception evt) {
            evt.getStackTrace();
        }

        byte[] big = output.toByteArray();
        return big;
    }

  
    /*****************************************************************************
     * Name : concatenateACK
     * Purpose : Concatenate the ACK message when sending a RESET command
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     * 
     * @param dlc
     *  *************************************************************************/
    byte[] concatenateACK(byte dlc) {  //THIS FUNCTION IS USED FOR RESET COMMAND!!!!!!!!!!!!!!!!!!!!!NOT DATA_GET
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try {
            output.write(this.EGNOS_Header.versionNum);
            output.write(this.EGNOS_Header.msgType);
            output.write(this.EGNOS_Header.flowType);
            output.write(this.EGNOS_Header.dataLength);
            output.write(this.EGNOS_Header.headerLength);
            output.write(this.EGNOS_Header.originAddress);
            output.write(this.EGNOS_Header.originPort);
            output.write(this.EGNOS_Header.destinationAddress);
            output.write(this.EGNOS_Header.destinationPort);
            output.write(this.EGNOS_Header.timeStamp);
            output.write(this.EGNOS_Header.spare);
            output.write(this.EGNOS_Header.originalDestinationAddress);
            output.write(this.EGNOS_Header.originalTime);
            output.write(this.EGNOS_Header.fullMessageCRC);
            output.write(this.EGNOS_Cmd.sectionIdentifier);
            output.write(this.EGNOS_Cmd.sectionLength);
            output.write(dlc);

        } catch (Exception evt) {
            evt.getStackTrace();
        }

        byte[] big = output.toByteArray();
        return big;
    }

    /**
     * ***************************************************************************
     * Name : computeCRC 
     * Purpose : compute the Cyclic Redundancy Check 
     * Argument I/O: byte array containing the whole message 
     * I/O Files: no input file
     * Returns :.
     * ************************************************************************
     */
    void computeCRC(byte[] data) {

        String crcString;
        int crcLength;
        int fullLength = 8, reducedLength = 7;

        System.out.println("COMPUTING CRC...");
        System.out.println("Data without CRC:");
        for (int i=0;i<data.length;i++)
            System.out.printf("%02X ", data[i]);
        System.out.println("");
        Checksum checksum = new CRC32();

        //Update the current checksum with the specified array of bytes
        checksum.update(data, 0, data.length);

        //Get the current checksum value
        long checksumValue = checksum.getValue();
        crcString = Long.toHexString(checksumValue);
        crcLength = crcString.length();
        System.out.println("Computed CRC long: " + checksumValue);
        System.out.println("Computed CRC: "+crcString.toUpperCase());
        System.out.println("Computed CRC length: " + crcLength);

        //If CRC is 8 bytes long
        if (crcLength == fullLength) {
            //Convert string to byte
            crcByte1 = Byte.parseByte(crcString.substring(0, 1), 16);
            crcByte2 = Byte.parseByte(crcString.substring(1, 2), 16);
            crcByte3 = Byte.parseByte(crcString.substring(2, 3), 16);
            crcByte4 = Byte.parseByte(crcString.substring(3, 4), 16);
            crcByte5 = Byte.parseByte(crcString.substring(4, 5), 16);
            crcByte6 = Byte.parseByte(crcString.substring(5, 6), 16);
            crcByte7 = Byte.parseByte(crcString.substring(6, 7), 16);
            crcByte8 = Byte.parseByte(crcString.substring(7, 8), 16);

            mergeCRC();
        } //If CRC is 7 bytes long
        else if (crcLength == reducedLength) {
            crcByte1 = Byte.parseByte(crcString.substring(0, 1), 16);
            crcByte2 = Byte.parseByte(crcString.substring(1, 2), 16);
            crcByte3 = Byte.parseByte(crcString.substring(2, 3), 16);
            crcByte4 = Byte.parseByte(crcString.substring(3, 4), 16);
            crcByte5 = Byte.parseByte(crcString.substring(4, 5), 16);
            crcByte6 = Byte.parseByte(crcString.substring(5, 6), 16);
            crcByte7 = Byte.parseByte(crcString.substring(6, 7), 16);

            mergeReduced7CRC();
        } //If CRC is 6 bytes long
        else if (crcLength == reducedLength - 1) {
            crcByte1 = Byte.parseByte(crcString.substring(0, 1), 16);
            crcByte2 = Byte.parseByte(crcString.substring(1, 2), 16);
            crcByte3 = Byte.parseByte(crcString.substring(2, 3), 16);
            crcByte4 = Byte.parseByte(crcString.substring(3, 4), 16);
            crcByte5 = Byte.parseByte(crcString.substring(4, 5), 16);
            crcByte6 = Byte.parseByte(crcString.substring(5, 6), 16);

            mergeReduced6CRC();
        }

    }

    /**
     * ***************************************************************************
     * Name : addCRC 
     * Purpose : add the computed CRC to the whole message
     * Argument I/O: CRC bytes 
     * I/O Files: 
     * Returns :.
     * ************************************************************************
     */
    void addCRC(byte[] a, byte crc1, byte crc2, byte crc3, byte crc4) {

        int startOfCRC = 27;

        a[startOfCRC++] = crc1;
        a[startOfCRC++] = crc2;
        a[startOfCRC++] = crc3;
        a[startOfCRC++] = crc4;

        replaceCRC(crc1, crc2, crc3, crc4);
    }

    /*****************************************************************************
     * Name : replaceCRC
     * Purpose : Put computed CRC in fullMessageCRC
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :.
     *  *************************************************************************/
    void replaceCRC(byte crc1, byte crc2, byte crc3, byte crc4) {

        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try {
            output.write(crc1);
            output.write(crc2);
            output.write(crc3);
            output.write(crc4);
        } catch (Exception evt) {
            evt.getStackTrace();
        }

        this.EGNOS_Header.fullMessageCRC = output.toByteArray();
    }

    /**
     * ***************************************************************************
     * Name : mergeCRC 
     * Purpose : merge the CRC bytes together 
     * Argument I/O: separated CRC bytes 
     * I/O Files: no input file 
     * Returns : nothing.
     * ************************************************************************
     */
    void mergeCRC() {

        int temp = crcByte1;
        int temp2 = crcByte2;

        //Byte1
        temp = temp << 4;
        temp = temp | temp2;
        crcByte1 = (byte) temp;
//        System.out.printf("Merged crcByte1 = %2X\n", crcByte1);

        //Byte2
        temp = crcByte3;
        temp2 = crcByte4;
        temp = temp << 4;
        temp = temp | temp2;
        crcByte2 = (byte) temp;
//        System.out.printf("Merged crcByte2 = %2X\n", crcByte2);

        //Byte3
        temp = crcByte5;
        temp2 = crcByte6;
        temp = temp << 4;
        temp = temp | temp2;
        crcByte3 = (byte) temp;
//        System.out.printf("Merged crcByte3 = %2X\n", crcByte3);

        //Byte4
        temp = crcByte7;
        temp2 = crcByte8;
        temp = temp << 4;
        temp = temp | temp2;
        crcByte4 = (byte) temp;
//        System.out.printf("Merged crcByte4 = %2X\n", crcByte4);

    }

    /**
     * ***************************************************************************
     * Name : mergeReduced7CRC 
     * Purpose : merge the CRC bytes together 
     * Argument I/O: separated CRC bytes 
     * I/O Files: no input file 
     * Returns : nothing.
     * ************************************************************************
     */
    void mergeReduced7CRC() {

        int temp = crcByte2;
        int temp2 = crcByte3;

        //Byte1
//        System.out.printf("Merged crcByte1 = %2X\n", crcByte1);
        //Byte2
        temp = temp << 4;
        temp = temp | temp2;
        crcByte2 = (byte) temp;
//        System.out.printf("Merged crcByte2 = %2X\n", crcByte2);

        //Byte3
        temp = crcByte4;
        temp2 = crcByte5;
        temp = temp << 4;
        temp = temp | temp2;
        crcByte3 = (byte) temp;
//        System.out.printf("Merged crcByte3 = %2X\n", crcByte3);

        //Byte4
        temp = crcByte6;
        temp2 = crcByte7;
        temp = temp << 4;
        temp = temp | temp2;
        crcByte4 = (byte) temp;
//        System.out.printf("Merged crcByte4 = %2X\n", crcByte4);

    }

    /**
     * ***************************************************************************
     * Name : mergeReduced6CRC 
     * Purpose : merge the CRC bytes together 
     * Argument I/O: separated CRC bytes 
     * I/O Files: no input file 
     * Returns : nothing.
     * ************************************************************************
     */
    void mergeReduced6CRC() {

        int temp = crcByte1;
        int temp2 = crcByte2;

        //Byte1
        crcByte1 = 0;
//        System.out.printf("Merged crcByte1 = %2X\n", crcByte1);

        //Byte2
        temp = temp << 4;
        temp = temp | temp2;
        crcByte2 = (byte) temp;
//        System.out.printf("Merged crcByte2 = %2X\n", crcByte2);

        //Byte3
        temp = crcByte3;
        temp2 = crcByte4;
        temp = temp << 4;
        temp = temp | temp2;
        crcByte3 = (byte) temp;
//        System.out.printf("Merged crcByte3 = %2X\n", crcByte3);

        //Byte4
        temp = crcByte5;
        temp2 = crcByte6;
        temp = temp << 4;
        temp = temp | temp2;
        crcByte4 = (byte) temp;
//        System.out.printf("Merged crcByte4 = %2X\n", crcByte4);
    }

}
