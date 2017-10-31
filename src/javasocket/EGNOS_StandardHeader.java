/***************************************************************************
 * Copyright : Thales Alenia Space
 * Project: EGNOS
 * File: EGNOS_StandardHeader.java
 * Date: 20/05/2016
 * Purpose : EGNOS header
 * Language : Java
 * Author : Kevin HANG
 * History :
 *
 * Version | Date | Name | Change History
 * 01.00 | 20/05/16 | KH | First Creation
 *.
 ***************************************************************************/
package javasocket;

import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import org.joda.time.DateTime;
import org.joda.time.Duration;

/*****************************************************************************
 * Class Name : EGNOS_StandardHeader
 * Purpose : Contains the Header of an EGNOS message.
 * *************************************************************************/
public class EGNOS_StandardHeader {
    
    byte versionNum; // never changes
    byte msgType;
    byte flowType;
    byte[] dataLength = new byte[2];
    byte[] headerLength = new byte[2];
    byte[] originAddress = new byte[2]; 
    byte originPort; // never changes
    byte[] destinationAddress = new byte[2];
    byte destinationPort; // never changes
    byte[] timeStamp = new byte[6];
    byte[] spare = new byte[4];
    byte[] originalDestinationAddress = new byte[2]; // never changes
    byte[] originalTime = new byte[2]; // never changes
    byte[] fullMessageCRC = new byte[4];
    int hLen;
    
    
    public EGNOS_StandardHeader(byte mType, byte fType, byte []hLength, byte [] origAddress, byte [] destAddress, byte []sp) {
        byte vNum = 0x01;
        versionNum = vNum;
        msgType = mType;
        flowType = fType;
        dataLength = new byte[] {(byte) 0x00,(byte) computeHeaderLength(this)};
        headerLength = hLength;
        originAddress = origAddress;
        originPort = 0x00;
        destinationAddress = destAddress;
        destinationPort = 0x00;
        timeStamp = computeTimeStamp();
        spare = sp;
        originalDestinationAddress = new byte[]{(byte) 0x00, (byte) 0x00};
        originalTime = new byte[]{(byte) 0x00, (byte) 0x00};
        fullMessageCRC = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        
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
     * Returns :
     *  *************************************************************************/
    public final void resetStdOutput() {
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
}
    
    /*****************************************************************************
     * Name : computeHeaderLength
     * Purpose : Compute the length of Header
     * Argument I/O: Header
     * I/O Files: No input file
     * Returns : length of header
     *
     * @param stdHeader
     * @return  *************************************************************************/
    public int computeHeaderLength(EGNOS_StandardHeader stdHeader) {
        int vNumLen = 1, mTypeLen = 1, fTypeLen = 1, oPortLen = 1, dPortLen = 1;
        hLen = vNumLen+mTypeLen+fTypeLen+dataLength.length+headerLength.length+originAddress.length+oPortLen+destinationAddress.length+dPortLen+timeStamp.length+spare.length+originalDestinationAddress.length+originalTime.length+fullMessageCRC.length;
        
        return hLen;
    }
    
    /*****************************************************************************
     * Name : computeTimeStamp
     * Purpose : Compute timestamp in seconds since 8/22/99
     * Argument I/O: 
     * I/O Files: No input file
     * Returns : Byte array containing timestamp
     *
     * @return  *************************************************************************/
    public byte [] computeTimeStamp() {
        
        long diff;
        long seconds;
        int month = 8, day = 22, year = 1999;
        int hour = 2, minute = 0, second = 0, millisecond = 0;
        
        byte[] time = new byte[6];
        
        //Get current time
        DateTime today = new DateTime();
        DateTime gpsTimeRollover = new DateTime()
                .withDate(year, month, day)
                .withTime(hour, minute, second, millisecond);
        Duration timeDiff = new Duration(gpsTimeRollover,today);
        seconds = timeDiff.getStandardSeconds();

        //Convert Long to Byte[]
        for (int i = time.length-1; i>=0 ;i--) {
            time[i]=(byte)(seconds & 0xFF);
            seconds >>=8;
        }
        
        //Bit shifting in the byte array
        byte temp = time[0];
        System.arraycopy(time, 1, time, 0, time.length-1);
        time[time.length-1]=temp;

        System.arraycopy(time, 1, time, 0, time.length-1);
        time[time.length-1]=temp;
        
        return time;
    }
    
    /*****************************************************************************
     * Name : printHeader
     * Purpose : Print header
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     *
     * @throws java.io.FileNotFoundException *************************************************************************/
    public void printHeader() throws FileNotFoundException {
        System.out.println();
        System.out.println("***HEADER***");
        System.out.println();
        System.out.printf("versionNum = %02X \n",this.versionNum);
        System.out.printf("msgType = %02X \n",this.msgType);
        System.out.printf("flowType = %02X \n",this.flowType);
        System.out.printf("dataLength :");
        for (int i=0;i<this.dataLength.length;i++)
        {
            System.out.printf("%02X ",this.dataLength[i]);
        }
        System.out.println("");
        System.out.printf("headerLength :");
        for (int i=0;i<this.headerLength.length;i++)
        {
            System.out.printf("%02X ",this.headerLength[i]);
        }
        System.out.println("");
        System.out.printf("originAddr :");
        for (int i=0;i<this.originAddress.length;i++)
        {
            System.out.printf("%02X ",this.originAddress[i]);
        }
        System.out.println("");
        System.out.printf("originPort = %02X \n",this.originPort);
        System.out.printf("destAddr :");
        for (int i=0;i<this.destinationAddress.length;i++)
        {
            System.out.printf("%02X ",this.destinationAddress[i]);
        }
        System.out.println("");
        
        
//        resetStdOutput();
//        System.out.println(new BigInteger(this.destinationAddress).intValue());
//        setLog();
        
        System.out.printf("destinationPort = %02X \n",this.destinationPort);
        System.out.printf("timeStamp :");
        for (int i=0;i<this.timeStamp.length;i++)
        {
            System.out.printf("%02X ",this.timeStamp[i]);
        }
        System.out.println("");
        System.out.printf("spare :");
        for (int i=0;i<this.spare.length;i++)
        {
            System.out.printf("%02X ",this.spare[i]);
        }
        System.out.println("");
        System.out.printf("originalDestinationAddress :");
        for (int i=0;i<this.originalDestinationAddress.length;i++)
        {
            System.out.printf("%02X ",this.originalDestinationAddress[i]);
        }
        System.out.println("");
        System.out.printf("originalTime :");
        for (int i=0;i<this.originalTime.length;i++)
        {
            System.out.printf("%02X ",this.originalTime[i]);
        }
        System.out.println("");
        System.out.printf("CRC :");
        for (int i=0;i<this.fullMessageCRC.length;i++)
        {
            System.out.printf("%02X ",this.fullMessageCRC[i]);
        }
        System.out.println("\n");
    }
}
