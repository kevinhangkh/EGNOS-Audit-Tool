/**
 * *************************************************************************
 * Copyright : Thales Alenia Space
 * Project: EGNOS
 * File: EGNOS_Client.java
 * Date: 20/05/2016
 * Purpose : Send DATA_GET commands to assets and analyze the response
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.Snmp;
import org.snmp4j.TransportMapping;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;
import org.snmp4j.transport.DefaultUdpTransportMapping;
import javax.xml.parsers.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.*;
import javax.xml.transform.stream.*;
import org.w3c.dom.*;


/*****************************************************************************
 * Class Name : EGNOS_Client
 * Purpose : Main Class of the project. Create, send, receive, write & read.
 * *************************************************************************/
public class EGNOS_Client {
    
    //GLOBAL VARIABLES
    public static int count = 0;
    public static int [] egnosAddresses;
    public static int egnosAddress;
    public static String name;
    public static String[] names;
    public static boolean type = false;
    public static boolean socketTimeOut = false;
    
    public final String output = "output.csv";
    public final String log = "log.txt";
    public static String xml = "audit.xml";
    
    //XML elements
    public static Element auditElement;
    public static Element timeElement;
    public static Element assetElement;
    public static Element addrElement;
    public static Element assetNameElement;
    public static Element paramElement;
    public static Element paramNameElement;
    public static Element paramNumElement;
    public static Element versionElement;
    public static Element commonElement;
    
    public static int [] indexOfFEE;
    public static int [] indexOfCCF;
    public final String nameRimsA = "RIMSA";
    public final String nameRimsAG2 = "RIMSAG2";
    public final String nameRimsB = "RIMSB";
    public final String nameRimsC = "RIMSC";
    public final String nameNLES = "NLES";
    public final String nameNLESG2 = "NLESG2";
    public static String nameNLES_2 = "NLES";
    public static String nameNLESG2_2 = "NLESG2";
    public final String nameCPF_PS = "CPFPS";
    public final String nameCPF_CS = "CPFCS";
//    public final String nameCPF_CS1 = "CPFCS";
//    public final String nameCPF_CS2 = "CPFCS";
    public final String nameCCF = "CCF";
    public final String nameFEE = "FEE";
    public static int FEEFilecode = 0;
    public static int FEESysContact = 85;
    public static int FEESignSWVersion = 75;
    
    public static int splitCounter = 0;
    public static int rejectedCounter = 0;
    
    
    
    /*****************************************************************************
     * Name : whatTimeIsIt
     * Purpose : Returns the current time and date
     * Argument I/O: 
     * I/O Files: No input file
     * Returns : String containing time and date
     * 
     *
     * @return  
     *************************************************************************/
    public String whatTimeIsIt() {
        DateTime rightNow = new DateTime();
        DateTimeFormatter format = DateTimeFormat.forPattern("dd/MM/yyyy HH:mm:ss");
        
        return format.print(rightNow);
    }
    
     /*****************************************************************************
     * Name : readIPFile
     * Purpose : Read the list of IP addresses and EGNOS addresses 
     * Argument I/O: None  
     * I/O Files: No input file
     * Returns : String containing all IP addresses
     *
     * @return 
     * @throws java.io.IOException *************************************************************************/
    public String[] readIPFile() throws IOException {

        System.out.println(whatTimeIsIt());
        System.out.println();
        System.out.println("*************READING IP FILE*************");
        System.out.println();

        try (BufferedReader br = new BufferedReader(new FileReader("ip_addresses.txt"))) {
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            
            String[] everyStr;
            int[] egnosAddr;
            int indexOfIp = 0;
            int indexOfEGNOS = 1;
            int indexOfName = 2;
            int countFEE = 0;
            int countCCF = 0;
            List<String> listIP;

            //READ THE ENTIRE FILE AND COUNT LINES
            while (line != null) {
                sb.append(line);
                sb.append(" ");
                line = br.readLine();
                count++;
//                System.out.println("countLine = " + ++count);
            }
            //IF FILE EMPTY => EXIT
            if (count == 0) {
                System.out.println("IP file is empty");
                System.exit(0);
            }
            
            String everything = sb.toString();
            System.out.println("everything: " + everything);

            //SPLIT STRING EVERY SPACE CHARACTER
            everyStr = everything.split(" ");
            System.out.println("everyStr split \" \": ");
            for (String everyStr1 : everyStr) {
                System.out.println(everyStr1);
            }
            
            //STRING ARRAY AND INT ARRAY
            String[][] everyStr2 = new String[everyStr.length][];
            egnosAddr = new int[everyStr2.length];
            String[] localNames = new String[everyStr.length];
            
            //SPLIT STRINGS EVERY ";"
            for (int i = 0; i < everyStr.length; i++) {
                everyStr2[i] = everyStr[i].split(";");
            }

            //PUT ALL IP ADDRESSES IN STRING ARRAY
            for (int i = 0; i < everyStr.length; i++) {
                everyStr[i] = everyStr2[i][indexOfIp];
                System.out.println(everyStr[i]);
            }
            //PUT AND CONVERT TO INT ALL EGNOS ADDRESSES IN INT ARRAY
            for (int i = 0; i < everyStr2.length; i++) {
                egnosAddr[i] = Integer.valueOf(everyStr2[i][indexOfEGNOS]);
                System.out.println(egnosAddr[i]);
            }
            //PUT ALL NAMES IN STRING ARRAY
            System.out.println("Names: ");
            for (int i = 0; i < everyStr2.length; i++) {
                localNames[i] = everyStr2[i][indexOfName];
                System.out.println(localNames[i]);
                
                if (localNames[i].equals(nameFEE))
                    countFEE++;
                else if (localNames[i].equals(nameCCF))
                    countCCF++;
            }
            
            System.out.println("Count FEE: " + countFEE);
            indexOfFEE = new int[countFEE];
            System.out.println("Count CCF: " + countCCF);
            indexOfCCF = new int[countCCF];
            
            //PUT INDEX OF FEE AND CCF IN A INT ARRAY
            //THANKS FRANCOIS BALTAZAR
            int countTheFEE = 0;
            int countTheCCF = 0;
            for (int j = 0; j < localNames.length; j++) {
                if (localNames[j].equals(nameFEE))
                {
                    indexOfFEE[countTheFEE] = j;
                    countTheFEE++;
                }
                else if (localNames[j].equals(nameCCF)) {
                    indexOfCCF[countTheCCF] = j;
                    countTheCCF++;
                }
            }
            
            if (countFEE > 0) {
                System.out.println("index of FEE:");
                for (int i = 0; i < indexOfFEE.length; i++) {
                    System.out.printf("%d ", indexOfFEE[i]);
                }
                System.out.println("");
            }
            
            if (countCCF > 0) {
                System.out.println("index of CCF:");
                for (int i = 0; i < indexOfCCF.length; i++) {
                    System.out.printf("%d ", indexOfCCF[i]);
                }
                System.out.println("");
            }
            
            
            //IF ONLY 1 LINE IN TXT FILE, PUT THE EGNOS ADDRESS IN AN INTEGER
            if (count == 1) {
                egnosAddress = egnosAddr[0];
                System.out.printf("One egnos address: 0x%02X", egnosAddress);
                System.out.println("");
                name = localNames[0];
                System.out.printf("One name: " + name);
            }
            //IF SEVERAL LINES, PUT ALL EGNOS ADDRESSES IN AN INTEGER ARRAY AND ALL NAMES IN STRING ARRAY
            else if (count > 1) {
                //EGNOS ADDRESSES
                egnosAddresses = new int[egnosAddr.length];
                System.out.println("length of egnosAddresses: " + egnosAddresses.length);
                System.arraycopy(egnosAddr, 0, egnosAddresses, 0, egnosAddr.length);
                
                System.out.printf("%d egnos addresses:\n", egnosAddresses.length);
                for (int i = 0; i < egnosAddresses.length; i++) {
                    System.out.printf("%02X ", egnosAddresses[i]);
                }
                System.out.println("");
                
                //NAMES
                names = new String[localNames.length];
                System.out.println("length of names: " + names.length);
                System.arraycopy(localNames, 0, names, 0, localNames.length);
                
                System.out.printf("%d names:\n", names.length);
                for (String name1 : names) {
                    System.out.printf("%s ", name1);
                }
                System.out.println("");
            }
            
            //CONVERT STRING ARRAY TO LIST OF STRINGS
            listIP = new ArrayList<>(Arrays.asList(everyStr));
            
            //TEST ALL IP ADDRESSES
            for (int i = 0; i < listIP.size(); i++) {
                System.out.println(listIP.get(i));
                CheckIPAddress testIPAddress = new CheckIPAddress(listIP.get(i));
                //IF IP ADDRESS IS NOT VALID, REMOVE IT FROM THE LIST
                if (testIPAddress.checkValidity()) {
                    listIP.remove(i);
                    i--;
                }
            }
//            System.out.println(listIP);

            //CONVERT LIST OF STRINGS TO STRING ARRAY CONTAINING ONLY VALID IP ADDRESSES
            everyStr = listIP.toArray(new String[0]);
            System.out.println("\nValid IP addresse(s): ");
            for (int i = 0; i < everyStr.length; i++) {
                System.out.println(everyStr[i]);
            }
            
            return everyStr;
            
        }    
    }

    /*****************************************************************************
     * Name : readFileCode
     * Purpose : Read the file codes corresponding to a specific IP address
     * Argument I/O: Name of the asset 
     * I/O Files: No input file
     * Returns : Byte array containing the file codes
     *    
     * @param name
     * @return 
     * @throws java.io.IOException *************************************************************************/    
    public byte [] readFileCode(String name) throws IOException {

        String choice = null;
        String txt = ".txt";

        String fileCPFCS = "CPF_CS.txt";
        
        switch (name) {
            case nameRimsA:
                choice = nameRimsA + txt;
                break;
            case nameRimsAG2:
                choice = nameRimsAG2 + txt;
                break;
            case nameRimsB:
                choice = nameRimsB + txt;
                break;
            case nameRimsC:
                choice = nameRimsC + txt;
                break;
            case nameNLES:
                choice = nameNLES + txt;
                break;
            case nameNLESG2:
                choice = nameNLESG2 + txt;
                break;
//            case nameCPF_CS1:
//            case nameCPF_CS2:
//                choice = fileCPFCS; //same file for both CPF CS
//                break;
            case nameCPF_CS:
                choice = nameCPF_CS + txt;
                break;
            case nameCPF_PS:
                choice = nameCPF_PS + txt;
                break;
            case nameCCF:
                choice = nameCCF + txt;
                break;
            default:
                System.err.println("IP address does not correspond to any asset");
                break;
        }
        
        System.out.println("Reading version file: ");
        try (BufferedReader br = new BufferedReader(new FileReader(choice))) {
            
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();
            String[] everyStr;

            while (line != null) {
                sb.append(line);
                sb.append(" ");
//                sb.append(System.lineSeparator()); //////THIS LINE IS EVIL//////
                line = br.readLine();
            }
            String everything = sb.toString();
            System.out.println("Parameters: " + everything);
           
//            System.out.println("everyStr: ");
            everyStr = everything.split(" ");
//            for (int j = 0; j < everyStr.length; j++) {
//                System.out.println(everyStr[j] + " ");
//            }
            
//            System.out.println("versions: ");
            int[] versions = new int[everyStr.length];

            //Convert String to int
            for (int i = 0; i < everyStr.length; i++) {
                versions[i] = Integer.parseInt(everyStr[i]);
//                System.out.println(versions[i] + " ");
            }
            
            //Convert int to byte
            byte[] listVer = new byte [versions.length];
            for (int i = 0; i < versions.length; i++) {
                listVer[i] = (byte) versions[i];
                System.out.printf("%02x  ", listVer[i]);
            }
            
            System.out.println("");

            return listVer;
        }
        
            
        
    }
    
    /*****************************************************************************
     * Name : createMessage
     * Purpose : Create an EGNOS message
     * Argument I/O: Name of the message and various parameters of the message header and command section 
     * I/O Files: No input file
     * Returns : Byte array containing the whole message
     *
     * @param name
     * @param msgType
     * @param flowType
     * @param headerLength
     * @param origAddress
     * @param destAddress
     * @param spare
     * @param sectionId
     * @param confirmKey
     * @param cmdType
     * @param cmdParam
     * @return
     * @throws java.io.FileNotFoundException  *************************************************************************/
    public byte [] createMessage(String name, byte msgType, byte flowType, byte []headerLength, byte [] origAddress, byte [] destAddress, byte []spare, 
            byte sectionId, byte [] confirmKey, byte cmdType, byte [] cmdParam) throws FileNotFoundException {
        
        byte[] entireMessage;
        boolean CCFMsg = false;
        boolean CCFACK = false;
        boolean resp = false;
        
        EGNOS_Message msg = new EGNOS_Message(name,CCFMsg,CCFACK,resp);
        msg.EGNOS_Header = new EGNOS_StandardHeader(msgType, flowType, headerLength, origAddress, destAddress, spare);
        msg.EGNOS_Cmd = new EGNOS_Command(sectionId, confirmKey, cmdType, cmdParam);
        msg.computeDataLength();
        entireMessage = msg.concatenate();
        msg.computeCRC(entireMessage);
        msg.addCRC(entireMessage, msg.crcByte1, msg.crcByte2, msg.crcByte3, msg.crcByte4);

        System.out.println("Complete Data Created Message:");
        for (int i = 0; i < entireMessage.length; i++) {
            System.out.printf("%02X ", entireMessage[i]);
        }
        System.out.println("\n");

        msg.EGNOS_Header.printHeader();
        msg.EGNOS_Cmd.printCmd();

        return entireMessage;
    }
    
    /*****************************************************************************
     * Name : createMessageCCF
     * Purpose : Creates a CCF Message
     * Argument I/O: None  
     * I/O Files: Name of the message and various parameters of the message header and command section
     * Returns : Byte array containing the entire message
     *
     * @param name
     * @param msgType
     * @param flowType
     * @param headerLength
     * @param origAddress
     * @param destAddress
     * @param spare
     * @param sectionId
     * @param confirmKey
     * @param cmdType
     * @param cmdParamCCF
     * @return
     * @throws java.io.FileNotFoundException *************************************************************************/
    public byte [] createMessageCCF(String name, byte msgType, byte flowType, byte []headerLength, byte [] origAddress, byte [] destAddress, byte []spare, 
            byte sectionId, byte [] confirmKey, byte cmdType, byte cmdParamCCF) throws FileNotFoundException {
        
        byte[] entireMessage;
        boolean CCFMsg = true;
        boolean CCFACK = false;
        boolean resp = false;
        
        EGNOS_Message msg = new EGNOS_Message(name,CCFMsg,CCFACK,resp);
        msg.EGNOS_Header = new EGNOS_StandardHeader(msgType, flowType, headerLength, origAddress, destAddress, spare);
        msg.EGNOS_Cmd_CCF = new EGNOS_Command_CCF(sectionId, confirmKey, cmdType, cmdParamCCF);
        msg.computeDataLength();
        entireMessage = msg.concatenate();
        msg.computeCRC(entireMessage);
        msg.addCRC(entireMessage, msg.crcByte1, msg.crcByte2, msg.crcByte3, msg.crcByte4);

        System.out.println("Complete Data Created Message:");
        for (int i = 0; i < entireMessage.length; i++) {
            System.out.printf("%02X ", entireMessage[i]);
        }
        System.out.println("\n");

        msg.EGNOS_Header.printHeader();
        msg.EGNOS_Cmd_CCF.printCmd();

        return entireMessage;
    }
    
    /*****************************************************************************
     * Name : createMessageCCF_ACK
     * Purpose : Creates the message sent before (122 bytes) CCF Message
     * Argument I/O: None  
     * I/O Files: Name of the message and various parameters of the message header and command section
     * Returns : Byte array containing the entire message
     *
     * @param name
     * @param msgType
     * @param flowType
     * @param headerLength
     * @param origAddress
     * @param destAddress
     * @param spare
     * @param sectionId
     * @param confirmKey
     * @param cmdType
     * @param cmdParamCCFACK
     * @return
     * @throws java.io.FileNotFoundException *************************************************************************/
    public byte [] createMessageCCF_ACK(String name, byte msgType, byte flowType, byte []headerLength, byte [] origAddress, byte [] destAddress, byte []spare, 
            byte sectionId, byte [] confirmKey, byte cmdType, byte[] cmdParamCCFACK) throws FileNotFoundException {
        
        byte[] entireMessage;
        boolean CCFMsg = false;
        boolean CCFACK = true;
        boolean resp = false;
        
        EGNOS_Message msg = new EGNOS_Message(name,CCFMsg,CCFACK,resp);
        msg.EGNOS_Header = new EGNOS_StandardHeader(msgType, flowType, headerLength, origAddress, destAddress, spare);
        msg.EGNOS_Cmd_CCF_ACK = new EGNOS_Command_CCF_ACK(sectionId, confirmKey, cmdType, cmdParamCCFACK);
        msg.computeDataLength();
        entireMessage = msg.concatenate();
        msg.computeCRC(entireMessage);
        msg.addCRC(entireMessage, msg.crcByte1, msg.crcByte2, msg.crcByte3, msg.crcByte4);

        System.out.println("Complete Data Created Message:");
        for (int i = 0; i < entireMessage.length; i++) {
            System.out.printf("%02X ", entireMessage[i]);
        }
        System.out.println("\n");

        msg.EGNOS_Header.printHeader();
        msg.EGNOS_Cmd_CCF_ACK.printCmd();

        return entireMessage;
    }
    
    /*****************************************************************************
     * Name : sendMessage
     * Purpose : Send the EGNOS message to a specific asset 
     * Argument I/O: IP address, EGNOS message and XML document
     * I/O Files: No input file
     * Returns :
     *
     * @param hostName
     * @param msg 
     * @param doc 
     *************************************************************************/
    public void sendMessage(String hostName, byte [] msg, Document doc) throws IOException {

        //Define the port number
        int portNumber = 32896;
        int timeOut = 1000;

        try (Socket sock = new Socket()) 
        {
            sock.connect(new InetSocketAddress(hostName, portNumber), timeOut); //HERE
            OutputStream dOutput = sock.getOutputStream();
            System.out.println();
            System.out.println("***NOW SENDING MESSAGE***");
            dOutput.write(msg);
            System.out.println("***MESSAGE SENT***");
            System.out.println();

            Thread t_getResponse = new Thread(new getResponse(sock, doc));
            t_getResponse.start();
            
            System.out.println("********THREAD STARTED*********");
            System.out.println();
            
            try {
                //Wait for t_getResponse to end
                t_getResponse.join();
            } catch (InterruptedException ex) {
                Logger.getLogger(EGNOS_Client.class.getName()).log(Level.SEVERE, null, ex);
            }
   
        } catch (UnknownHostException e) {
            System.err.println("Don't know about host " + hostName);
            System.exit(1);
//        } catch (IOException e) {
//            System.err.println("Couldn't get I/O for the connection to "
//                    + hostName);
//            System.exit(1);
        } catch (SocketTimeoutException e) {
            //IF ASSET NOT RESPONDING
            socketTimeOut = true;
            resetStdOutput();
            System.out.println("NOT CONNECTED");
            setLog();
        }
        
        System.out.println();
        System.out.println("********THREAD ENDED*********");
        System.out.println();
        
    }
    
    /*****************************************************************************
     * Name : writeColumnTitles
     * Purpose : Write the column titles in the output file
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :.
     * 
     * *************************************************************************/
    public void writeColumnTitles() {
        File file = new File(output);
        
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write("Timestamp" + ";" + "EGNOS Address" + ";" + "Parameter" + ";" + "Parameter number" + ";" + "Version" + System.lineSeparator());
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
    }
    
    /*****************************************************************************
     * Name : writeTime
     * Purpose : Write time and date in the output file
     * Argument I/O: None  
     * I/O Files: No input file
     * Returns :
     * .
     * *************************************************************************/
    public void writeTime() {
        File file = new File(output);
        DateTime rightNow = new DateTime();
        DateTimeFormatter format = DateTimeFormat.forPattern("dd/MM/yyyy HH:mm:ss");
        
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(format.print(rightNow) + ";");
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
    }
    
    /*****************************************************************************
     * Name : writeEGNOSAddr
     * Purpose : Write the EGNOS Address in the output file
     * Argument I/O: EGNOS address
     * I/O Files: No input file
     * Returns :
     *
     * @param egnosAddr *************************************************************************/
    public void writeEGNOSAddr(int egnosAddr) {
        File file = new File(output);
        
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(egnosAddr + ";");
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
    }
    
    /*****************************************************************************
     * Name : hexToInt
     * Purpose : Convert hexadecimal to integer
     * Argument I/O: byte array containing hex number
     * I/O Files: No input file
     * Returns : String containing the integer value
     *
     * @param data
     * @return 
     * @throws java.io.UnsupportedEncodingException *************************************************************************/
    public String hexToInt(byte [] data) throws UnsupportedEncodingException {
        int start = 1;
        int bitToInt = data[start];

        return String.valueOf(bitToInt);
    }
    
    /*****************************************************************************
     * Name : writeFileCode
     * Purpose : Write file code in the output file
     * Argument I/O: IP address and a String containing the file code number
     * I/O Files: No input file
     * Returns : 
     *
     * @param name
     * @param data
     * @param doc
     * @throws javax.xml.transform.TransformerException *************************************************************************/
    public void writeFileCode(String name, String data, Document doc, String egnosAddr) throws TransformerException {

        File file = new File(output);
        String fileCodeName = null;
        String newEgnosAddr;

        //Format EGNOS address XXX
//        if (egnosAddr.length() == 1)
//            newEgnosAddr = "00" + egnosAddr;
//        else if (egnosAddr.length() == 2);
//            newEgnosAddr = "0" + egnosAddr;
        
        switch (egnosAddr.length()) {
            case 1:
                newEgnosAddr = "00" + egnosAddr;
                break;
            case 2:
                newEgnosAddr = "0" + egnosAddr;
                break;
            default:
                newEgnosAddr = egnosAddr;
                }
        
        switch (name) {
            case nameRimsA:
            case nameRimsAG2:
                switch (data) {
                    case "65":
                        if (name.equals(nameRimsA))
                            fileCodeName = "RSACC020.EXE";
                        else if (name.equals(nameRimsAG2))
                            fileCodeName = "RSACC011.EXE";
                        break;
                    case "74":
                        fileCodeName = "RSASYS.CNF";
                        break;
                    case "75":
                        fileCodeName = "RSAOPER." + newEgnosAddr;
                        break;
                    case "76":
                        fileCodeName = "RSAEGNOS.CNF";
                        type = true;
                        break;
                    case "77":
                        fileCodeName = "RSA_ALM." + newEgnosAddr;
                        break;
                    case "80":
                        fileCodeName = "RSARS070.EXE";
                        break;
                    case "81":
                        fileCodeName = "RSARC060.EXE";
                        break;
                    case "82":
                        fileCodeName = "RSATRACK." + newEgnosAddr;
                        break;
                    default:
                        fileCodeName = "UNKNOWN";
                        break;
                }
                break;
            case nameRimsB:
                switch (data) {
                    case "64":
                        fileCodeName = "RSB_CSTARTUP";
                        break;
                    case "65":
                        fileCodeName = "rsbcc009.exe";
                        break;
                    case "69":
                        fileCodeName = "RSB_RRXSTARTUP";
                        break;
                    case "70":
                        fileCodeName = "RSBRS250.exe";
                        break;
                    case "74":
                        fileCodeName = "Rsbsyst.246";
                        break;
                    case "76":
                        fileCodeName = "Rsbegnos.246";
                        break;
                    case "77":
                        fileCodeName = "Rsbalman." + newEgnosAddr;
                        break;
                    case "79":
                        fileCodeName = "Rsboper.246";
                        break;
                    default:
                        fileCodeName = "UNKNOWN";
                        break;
                }
                break;
            case nameRimsC:
                switch (data) {
                    case "65":
                        fileCodeName = "CORE_EXECUTABLE";
                        break;
                    case "70":
                        fileCodeName = "RECEIVER_ZIP_FILE";
                        break;
                    case "71":
                        fileCodeName = "RECEIVER_MEDLL_SOFTWARE";
                        break;
                    case "72":
                        fileCodeName = "RECEIVER_L1L2-I";
                        break;
                    case "73":
                        fileCodeName = "RECEIVER_L1L2-II";
                        break;
                    case "74":
                        fileCodeName = "SYSTEM_PARAMETERS";
                        break;
                    case "75":
                        fileCodeName = "OPERATIONAL_PARAMETERS";
                        break;
                    case "76":
                        fileCodeName = "EGNOS_PARAMETERS";
                        break;
                    default:
                        fileCodeName = "UNKNOWN";
                        break;
                }
                break;
            case nameNLES:
                switch (data) {
                    case "64":
                        fileCodeName = "ER640113.EXE";
                        break;
                    case "70":
                        fileCodeName = "ER700207.EXE";
                        break;
                    case "75":
                        fileCodeName = "ER750207.EXE";
                        break;
                    case "76":
                        fileCodeName = "ER760206.EXE";
                        break;
                    case "80":
                        fileCodeName = "IR800851." + newEgnosAddr;
                        break;
                    case "81":
                        fileCodeName = "IR810853." + newEgnosAddr;
                        break;
                    case "82":
                        fileCodeName = "IR840123.INI";
                        type = true;
                        break;
                    default:
                        fileCodeName = "UNKNOWN";
                        break;
                }
                break;
            case nameNLESG2:
                switch (data) {
                    case "64":
                        fileCodeName = "ER640301.EXE";
                        break;
                    case "70":
                        fileCodeName = "ER700100.EXE";
                        break;
                    case "75":
                        fileCodeName = "ER750500.EXE";
                        break;
                    case "80":
                        fileCodeName = "IR801101." + newEgnosAddr;
                        break;
                    case "81":
                        fileCodeName = "IR811101." + newEgnosAddr;
                        break;
                    default:
                        fileCodeName = "UNKNOWN";
                        break;
                }
                break;
//            case nameCPF_CS1:
//            case nameCPF_CS2:
            case nameCPF_CS:
                switch (data) {
                    case "75":
                        fileCodeName = "RTMC_MASTER_EXECUTABLE";
                        break;
                    case "76":
                        fileCodeName = "ALGORITHM_EXECUTABLE1";
                        break;
                    case "77":
                        fileCodeName = "ALGORITHM_EXECUTABLE2";
                        break;
                    case "78":
                        fileCodeName = "ALGORITHM_EXECUTABLE3";
                        break;
                    case "79":
                        fileCodeName = "ALGORITHM_EXECUTABLE4";
                        break;
                    case "85":
                        fileCodeName = "CPFEGNOS.CNF";
                        type = true;
                        break;
                    case "86":
                        fileCodeName = "CCHOPER.CNF";
                        type = true;
                        break;
                    case "87":
                        fileCodeName = "CCHSYS." + newEgnosAddr;
                        break;
                    case "88":
                        fileCodeName = "CCHSITE." + newEgnosAddr;
                        break;
                    default:
                        fileCodeName = "UNKNOWN";
                        break;
                }
                break;
            case nameCPF_PS:
                switch (data) {
                    case "67":
                        fileCodeName = "CPFEGNOS.CNF";
                        type = true;
                        break;
                    case "69":
                        fileCodeName = "CPRIGP.CNF";
                        type = true;
                        break;
                    case "68":
                        fileCodeName = "CPROPER.CNF";
                        type = true;
                        break;
                    case "70":
                        fileCodeName = "CPRSITE." + newEgnosAddr;
                        break;
                    case "66":
                        fileCodeName = "CPRSYS." + newEgnosAddr;
                        break;
                    case "100":
                        fileCodeName = "CPPR1182.EXE";
                        break;
                    case "79":
                        fileCodeName = "CPPR2182.EXE";
                        break;
                    case "80":
                        fileCodeName = "CPPR3182.EXE";
                        break;
                    case "109":
                        fileCodeName = "CPRSCHED.PAR";
                        break;
                    default:
                        fileCodeName = "UNKNOWN";
                        break;
                }
                break;
            default:
                fileCodeName = "FILE CODE???";
                break;
        }


        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(fileCodeName + ";");
                writer.write(data + ";");
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
        
        //XML
        xmlParamNameNumber(doc, fileCodeName, data);

    }
    
    /*****************************************************************************
     * Name : writeLineSeparator
     * Purpose : Write line separator in the output file
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     * *************************************************************************/
    public void writeLineSeparator() {
        File file = new File(output);
        
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(System.lineSeparator());
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
    }
    
    /*****************************************************************************
     * Name : writeFEEParameter
     * Purpose : Write the FEE Parameter in the output file
     * Argument I/O: name of the parameter and XML document
     * I/O Files: No input file
     * Returns :
     * 
     * @param name
     * @param doc
     * @throws javax.xml.transform.TransformerException
     * *************************************************************************/
    public void writeFEEParameter(String name, Document doc) throws TransformerException {
        File file = new File(output);
        
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(name + ";");
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
        
        xmlParameter(doc);
        
        if (FEEFilecode == 0) {
            xmlParamNameNumber(doc, name, Integer.toString(FEESysContact));
        } else {
            xmlParamNameNumber(doc, name, Integer.toString(FEESignSWVersion));
        }
    }
    
    /*****************************************************************************
     * Name : writeFEEFileCode
     * Purpose : Write the FEE File Code in the output file
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     * *************************************************************************/
    public void writeFEEFileCode() {
        File file = new File(output);
        
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write("N/A" + ";");
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
        
        //xmlParamNameNumber(doc, name, name);
    }
    
    /*****************************************************************************
     * Name : writeFEEVersion
     * Purpose : Write the version in the output file
     * Argument I/O: Version and XML document
     * I/O Files: No input file
     * Returns :
     * 
     * @param version
     * @param doc
     * @throws javax.xml.transform.TransformerException
     * *************************************************************************/
    public void writeFEEVersion(String version, Document doc) throws TransformerException {
        File file = new File(output);
        
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(version + System.lineSeparator());
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
        
        xmlVersion(doc, version);
        xmlType(doc);
    }
    
    /*****************************************************************************
     * Name : getFEESysContact
     * Purpose : Get the SysContact version
     * Argument I/O: IP address and XML document
     * I/O Files: No input file
     * Returns :
     * 
     * @param FEEIPAddress
     * @param doc
     * @return 
     * @throws javax.xml.transform.TransformerException 
     * *************************************************************************/
    public String getFEESysContact(String FEEIPAddress, Document doc) throws TransformerException, FileNotFoundException{
        String returnValue = new String();
//        String nameParameter = "FEESysContact";

        //To write the Filecode in the XML
        FEEFilecode = 0;

        String nameParameter = "egnos.cfg.gz";
        boolean commandok = false;
        
        try {
            String oidValue = ".1.3.6.1.2.1.1.4.0";  // ends with 0 for scalar object

            int snmpVersion = SnmpConstants.version2c;

            String community = "public";

            // Create TransportMapping and Listen

            TransportMapping transport = new DefaultUdpTransportMapping();
            transport.listen();


            // Create Target Address object
            CommunityTarget comtarget = new CommunityTarget();
            comtarget.setCommunity(new OctetString(community));
            comtarget.setVersion(snmpVersion);
            //comtarget.setAddress(new UdpAddress(ipAddress + "/" + port));
            comtarget.setAddress(new UdpAddress(FEEIPAddress + "/161"));
            comtarget.setRetries(2);
            comtarget.setTimeout(1000);

            // Create the PDU object
            PDU pdu = new PDU();
            pdu.add(new VariableBinding(new OID(oidValue)));
            pdu.setType(PDU.GET);
            pdu.setRequestID(new Integer32(1));

            // Create Snmp object for sending data to Agent
            Snmp snmp = new Snmp(transport);

            System.out.println("Sending Request to Agent...");
            ResponseEvent response = snmp.send(pdu, comtarget);
            // Process Agent Response
            if (response != null) {
                System.out.println("Got Response from Agent");
                PDU responsePDU = response.getResponse();

                if (responsePDU != null) {
                    int errorStatus = responsePDU.getErrorStatus();
                    int errorIndex = responsePDU.getErrorIndex();
                    String errorStatusText = responsePDU.getErrorStatusText();

                    if (errorStatus == PDU.noError) {
                        //In CSV and XML
                        writeFEEParameter(nameParameter,doc);
                        writeFEEFileCode();
                        System.out.println("Snmp Get Response = " + responsePDU.getVariableBindings());
                        
//                        resetStdOutput();
//                        System.out.println("Snmp Get Response = " + responsePDU.getVariableBindings());
//                        setLog();
                        
                        returnValue = responsePDU.getVariableBindings().firstElement().getVariable().toString();
                        resetStdOutput();
                        System.out.println(returnValue);
                        setLog();
                        //FOR GOOD CSV FORMAT
                        //returnValue = returnValue.replace(";", " ");
                        commandok = true;
                    } else {
                        System.out.println("Error: Request Failed");
                        System.out.println("Error Status = " + errorStatus);
                        System.out.println("Error Index = " + errorIndex);
                        System.out.println("Error Status Text = " + errorStatusText);
                    }
                } else {
                    System.out.println("Error: Response PDU is null");
                }
            } else {
                System.out.println("Error: Agent Timeout... ");
            }
            snmp.close();
        } catch (IOException ex) {
            Logger.getLogger(EGNOS_Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (commandok == false){
            System.out.println("ERROR");
            resetStdOutput();
            System.out.println("N/A NO RESPONSE");
            setLog();
        }
            
        return (returnValue);
    }
    
    /*****************************************************************************
     * Name : getFEESignVersion
     * Purpose : Get the SignVersion version
     * Argument I/O: IP address and XML document
     * I/O Files: No input file
     * Returns :
     * 
     * @param FEEIPAddress
     * @param doc
     * @return 
     * @throws javax.xml.transform.TransformerException 
     * *************************************************************************/
    public String getFEESignSWVersion(String FEEIPAddress, Document doc) throws TransformerException, FileNotFoundException {
        String returnValue = new String();
        String nameParameter = "firmware";
        
        //To write the Filecode in the XML
        FEEFilecode = 1;
        
        boolean commandok = false;
        
        try {
            String oidValue = ".1.3.6.1.4.1.2717.255.3.7.0";  // ends with 0 for scalar object

            int snmpVersion = SnmpConstants.version2c;

            String community = "public";

            // Create TransportMapping and Listen

            TransportMapping transport = new DefaultUdpTransportMapping();
            transport.listen();


            // Create Target Address object
            CommunityTarget comtarget = new CommunityTarget();
            comtarget.setCommunity(new OctetString(community));
            comtarget.setVersion(snmpVersion);
            //comtarget.setAddress(new UdpAddress(ipAddress + "/" + port));
            comtarget.setAddress(new UdpAddress(FEEIPAddress + "/161"));
            comtarget.setRetries(2);
            comtarget.setTimeout(1000);

            // Create the PDU object
            PDU pdu = new PDU();
            pdu.add(new VariableBinding(new OID(oidValue)));
            pdu.setType(PDU.GET);
            pdu.setRequestID(new Integer32(1));

            // Create Snmp object for sending data to Agent
            Snmp snmp = new Snmp(transport);

            System.out.println("Sending Request to Agent...");
            ResponseEvent response = snmp.send(pdu, comtarget);
            // Process Agent Response
            if (response != null) {
                System.out.println("Got Response from Agent");
                PDU responsePDU = response.getResponse();

                if (responsePDU != null) {
                    int errorStatus = responsePDU.getErrorStatus();
                    int errorIndex = responsePDU.getErrorIndex();
                    String errorStatusText = responsePDU.getErrorStatusText();

                    if (errorStatus == PDU.noError) {
                        //In CSV and XML
                        writeFEEParameter(nameParameter, doc);
                        writeFEEFileCode();
                        System.out.println("Snmp Get Response = " + responsePDU.getVariableBindings());
                        
//                        resetStdOutput();
//                        System.out.println("Snmp Get Response = " + responsePDU.getVariableBindings());
//                        setLog();
                        
                        returnValue = responsePDU.getVariableBindings().firstElement().getVariable().toString();
                        resetStdOutput();
                        System.out.println(returnValue);
                        setLog();
                        //FOR GOOD CSV FORMAT
                        //returnValue = returnValue.replace(";", " ");
                        commandok = true;
                    } else {
                        System.out.println("Error: Request Failed");
                        System.out.println("Error Status = " + errorStatus);
                        System.out.println("Error Index = " + errorIndex);
                        System.out.println("Error Status Text = " + errorStatusText);
                    }
                } else {
                    System.out.println("Error: Response PDU is null");
                }
            } else {
                System.out.println("Error: Agent Timeout... ");
            }
            snmp.close();
        } catch (IOException ex) {
            Logger.getLogger(EGNOS_Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (commandok == false){
            System.out.println("ERROR");
            resetStdOutput();
            System.out.println("N/A NO RESPONSE");
            setLog();
        }
            
        return (returnValue);
    }
    
    /*****************************************************************************
     * Name : getFEEEGNOSAddress
     * Purpose : Get the EGNOS Address version
     * Argument I/O: IP address
     * I/O Files: No input file
     * Returns :
     * 
     * @param FEEIPAddress
     * @return 
     * *************************************************************************/
    public String getFEEEGNOSAddress(String FEEIPAddress) {
        String returnValue = new String();
        String nameParameter = "FEEEGNOSAddress";
        boolean commandok = false;
        
        try {
            String oidValue = ".1.3.6.1.4.1.2717.255.1.1.0";  // ends with 0 for scalar object

            int snmpVersion = SnmpConstants.version2c;

            String community = "public";

            // Create TransportMapping and Listen

            TransportMapping transport = new DefaultUdpTransportMapping();
            transport.listen();


            // Create Target Address object
            CommunityTarget comtarget = new CommunityTarget();
            comtarget.setCommunity(new OctetString(community));
            comtarget.setVersion(snmpVersion);
            //comtarget.setAddress(new UdpAddress(ipAddress + "/" + port));
            comtarget.setAddress(new UdpAddress(FEEIPAddress + "/161"));
            comtarget.setRetries(2);
            comtarget.setTimeout(1000);

            // Create the PDU object
            PDU pdu = new PDU();
            pdu.add(new VariableBinding(new OID(oidValue)));
            pdu.setType(PDU.GET);
            pdu.setRequestID(new Integer32(1));

            // Create Snmp object for sending data to Agent
            Snmp snmp = new Snmp(transport);

            System.out.println("Sending Request to Agent...");
            ResponseEvent response = snmp.send(pdu, comtarget);
            // Process Agent Response
            if (response != null) {
                System.out.println("Got Response from Agent");
                PDU responsePDU = response.getResponse();

                if (responsePDU != null) {
                    int errorStatus = responsePDU.getErrorStatus();
                    int errorIndex = responsePDU.getErrorIndex();
                    String errorStatusText = responsePDU.getErrorStatusText();

                    if (errorStatus == PDU.noError) {
//                        writeFEEParameter(nameParameter);
//                        writeFEEFileCode();
                        System.out.println("Snmp Get Response = " + responsePDU.getVariableBindings());
                        returnValue = responsePDU.getVariableBindings().firstElement().getVariable().toString();
//                        returnValue = returnValue.replace(";", " ");
                        commandok = true;
                    } else {
                        System.out.println("Error: Request Failed");
                        System.out.println("Error Status = " + errorStatus);
                        System.out.println("Error Index = " + errorIndex);
                        System.out.println("Error Status Text = " + errorStatusText);
                    }
                } else {
                    System.out.println("Error: Response PDU is null");
                }
            } else {
                System.out.println("Error: Agent Timeout... ");
            }
            snmp.close();
        } catch (IOException ex) {
            Logger.getLogger(EGNOS_Client.class.getName()).log(Level.SEVERE, null, ex);
        }
        if (commandok == false)
            System.out.println("ERROR");
        return (returnValue);
    }
    
    /*****************************************************************************
     * Name : initLog
     * Purpose : INITIALIZATION !!! PUT ONCE AT THE BEGINNING !!! Redirect the output to a log file
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     * 
     * @throws java.io.FileNotFoundException *************************************************************************/
    public void initLog() throws FileNotFoundException {
        PrintStream out = new PrintStream(new FileOutputStream(log));
        System.setOut(out);
    }
    
    /*****************************************************************************
     * Name : setLog
     * Purpose : Redirect the output to a log file
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     * 
     * @throws java.io.FileNotFoundException *************************************************************************/
    public void setLog() throws FileNotFoundException {
        PrintStream out = new PrintStream(new FileOutputStream(log,true));
        System.setOut(out);
    }
    
    /*****************************************************************************
     * Name : resetStdOutput
     * Purpose : Redirect the output to the standard output
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     *  *************************************************************************/
    public void resetStdOutput() {
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
}
    
//    public void log(String str){
//        File file = new File(log);
//        
//        System.out.println(str);
//        try {
//            try (FileWriter writer = new FileWriter(file, true)) {
//                writer.write(str);
//                writer.flush();
//            }
//
//        } catch (IOException ex) {
//            System.out.println("Error while writing in the file");
//        }
//    }
    
    /*****************************************************************************
     * Name : xmlInit
     * Purpose : Itinialize the XML file
     * Argument I/O: XML document
     * I/O Files: No input file
     * Returns :
     * 
     *  
     * @param doc
     * @throws javax.xml.transform.TransformerException
     *************************************************************************/
    public void xmlInit(Document doc) throws TransformerException{
        
            //Audit element
            auditElement = doc.createElement("audit");
            doc.appendChild(auditElement);
            
            //Write in XML
            xmlWrite(doc);
    }
    
    /*****************************************************************************
     * Name : xmlTime
     * Purpose : Write the timestamp in the XML file
     * Argument I/O: XML document
     * I/O Files: No input file
     * Returns :
     * 
     *  
     * @param doc
     * @throws javax.xml.transform.TransformerException
     * @throws javax.xml.parsers.ParserConfigurationException
     *************************************************************************/
    public void xmlTime(Document doc) throws TransformerException, ParserConfigurationException{
        
        DateTime rightNow = new DateTime();
        DateTimeFormatter format = DateTimeFormat.forPattern("dd/MM/yyyy HH:mm:ss");
        
        //Time stamp
        timeElement = doc.createElement("timestamp");
        auditElement.appendChild(timeElement);
        timeElement.appendChild(doc.createTextNode(format.print(rightNow)));
        
        //Write in XML
        xmlWrite(doc);
    }
    
    /*****************************************************************************
     * Name : xmlEgnosAddr
     * Purpose : Write elements : asset and egnos_address
     * Argument I/O: XML document and EGNOS address
     * I/O Files: No input file
     * Returns :
     * 
     *  
     * @param doc
     * @param egnosAddr
     * @throws javax.xml.transform.TransformerException
     *************************************************************************/
    public void xmlEgnosAddr(Document doc, String egnosAddr) throws TransformerException, FileNotFoundException{
        
        String newEgnosAddr;
        resetStdOutput();
        
        switch (egnosAddr.length()) {
            case 1:
                newEgnosAddr = "00" + egnosAddr;
                System.out.println(newEgnosAddr);
                break;
            case 2:
                newEgnosAddr = "0" + egnosAddr;
                System.out.println(newEgnosAddr);
                break;
            case 3:
                newEgnosAddr = egnosAddr;
                System.out.println(newEgnosAddr);
                break;
            default:
                newEgnosAddr = egnosAddr;
                break;
                }
        
        setLog();
        
        assetElement = doc.createElement("asset");
        auditElement.appendChild(assetElement);
        addrElement = doc.createElement("egnos_address");
        assetElement.appendChild(addrElement);
        addrElement.appendChild(doc.createTextNode(newEgnosAddr));
        
        //Write in XML
        xmlWrite(doc);
    }
    
    public void xmlAssetName(String name ,Document doc) throws TransformerException{
        
        assetNameElement = doc.createElement("asset_name");
        assetElement.appendChild(assetNameElement);
        assetNameElement.appendChild(doc.createTextNode(name));
        
        //Write in XML
        xmlWrite(doc);
    }
    
    /*****************************************************************************
     * Name : xmlParameter
     * Purpose : Write elements : parameter
     * Argument I/O: XML document
     * I/O Files: No input file
     * Returns :
     * 
     *  
     * @param doc
     * @throws javax.xml.transform.TransformerException
     *************************************************************************/
    public void xmlParameter(Document doc) throws TransformerException{
        
        paramElement = doc.createElement("parameter");
        assetElement.appendChild(paramElement);
        
        //Write in XML
        xmlWrite(doc);
    }
    
    /*****************************************************************************
     * Name : xmlParamNameNumber
     * Purpose : Write elements : name and number
     * Argument I/O: XML document, parameter name and number
     * I/O Files: No input file
     * Returns :
     * 
     *  
     * @param doc
     * @param name
     * @param number
     * @throws javax.xml.transform.TransformerException
     *************************************************************************/
    public void xmlParamNameNumber(Document doc, String name, String number) throws TransformerException{
        
        //Name
        paramNameElement = doc.createElement("name");
        paramElement.appendChild(paramNameElement);
        paramNameElement.appendChild(doc.createTextNode(name));
        
        //Number
        paramNumElement = doc.createElement("number");
        paramElement.appendChild(paramNumElement);
        paramNumElement.appendChild(doc.createTextNode(number));
        
        //Write in XML
        xmlWrite(doc);
    }
    
    /*****************************************************************************
     * Name : xmlVersion
     * Purpose : Write version
     * Argument I/O: XML document and version
     * I/O Files: No input file
     * Returns :
     * 
     *  
     * @param doc
     * @param version
     * @throws javax.xml.transform.TransformerException
     *************************************************************************/
    public void xmlVersion(Document doc, String version) throws TransformerException{
        
        //Attempt to remove invalid XML characters
        //String xmlPattern = "[^" + "\u0009\r\n" + "\u0020-\uD7FF" + "\uE000-\uFFFD" + "\ud800\udc00-\udbff\udfff" + "]";
        //String xmlPattern = "&#0;";
        //version = version.replaceAll(xmlPattern, "");
        
        versionElement = doc.createElement("version");
        paramElement.appendChild(versionElement);
        versionElement.appendChild(doc.createTextNode(version));
        
        //Write in XML
        xmlWrite(doc);
    }
    
    public void xmlType(Document doc) throws TransformerException{
        
        String str;
        commonElement = doc.createElement("type");
        paramElement.appendChild(commonElement);
        if (type)
            str = "Common";
        else
            str = "Specific";
        commonElement.appendChild(doc.createTextNode(str));
        
        //Write in XML
        xmlWrite(doc);
        
        type = false;
    }
    
    /*****************************************************************************
     * Name : xmlWrite
     * Purpose : Write everything in the XML file
     * Argument I/O: XML document
     * I/O Files: No input file
     * Returns :
     * 
     *  
     * @param doc
     * @throws javax.xml.transform.TransformerConfigurationException
     * @throws javax.xml.transform.TransformerException
     *************************************************************************/
    public void xmlWrite(Document doc) throws TransformerConfigurationException, TransformerException{
        //Write in XML
            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer trans = transFactory.newTransformer();
            DOMSource src = new DOMSource(doc);
            StreamResult res = new StreamResult(new File(xml));
            trans.transform(src, res);
    }
    
    /*****************************************************************************
     * Name : main
     * Purpose : Main function of the program
     * Argument I/O: None  
     * I/O Files: No input file
     * Returns : 
     * 
     * @param args the command line arguments
     * @throws java.io.IOException
     * @throws java.lang.InterruptedException
     * @throws javax.xml.transform.TransformerException
     * @throws javax.xml.parsers.ParserConfigurationException
     */
    @SuppressWarnings("empty-statement")
    public static void main(String[] args) throws IOException, InterruptedException, TransformerException, ParserConfigurationException {
        
//        System.out.println("AUDIT STARTED\n*********\n");
        
        /////////////PARAMETERS FOR DATA_GET///////////////
        //HEADER
        byte msgType = 0x6e;
        byte flowType = 0x21;
        byte[] headerLength = new byte[]{(byte) 0x00, (byte) 0x1f};
        byte[] originAddress = new byte[]{(byte) 0x01, (byte) 0x94};
//        byte[] originAddress = new byte[]{(byte) 0x01, (byte) 0x92};//TEST CPF PS
//        byte[] originAddress = new byte[]{(byte) 0x01, (byte) 0x91}; //ACK CCF
        byte[] destinationAddress;
        byte[] spare = new byte[]{(byte) 0x29, (byte) 0x00, (byte) 0x00, (byte) 0x00};

        //COMMAND
        byte sectionIdentifier = 0x65;
        byte[] confirmationKey = new byte[] {(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x00};
        byte commandType = 0x1f;
        byte[] commandParameter = new byte[] {(byte)0x01, (byte)0x00};
        byte commandParameterCCF;
        
        byte[] wholeMessage = null;
        
        String[] listIPAddr;
        byte[] listFileCode;
        boolean next = false;
        /////////////PARAMETERS FOR DATA_GET///////////////

        /////////////PARAMETERS FOR CCF ACK/////////////// --------------------- DOESN'T WORK
        //HEADER
        byte ACKmsgType = (byte) 0xa0;
        byte ACKflowType = 0x20;
        
        //COMMAND
        byte ACKsectionIdentifier = 0x00;
        byte[] ACKconfirmationKey = new byte[] {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xC0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0x03, (byte) 0x00, (byte) 0x00};
        byte ACKcommandType = 0x00;
        byte[] ACKcommandParameter = new byte[] {
            (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x31, (byte) 0x00, (byte) 0x0C, (byte) 0x0F, (byte) 0xFF, 
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x77, (byte) 0xFF, (byte) 0xFF, (byte) 0x5F, (byte) 0x5F,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x7F, (byte) 0xFC, (byte) 0xFF, (byte) 0x0F, (byte) 0xFF, (byte) 0xBF, (byte) 0x7F,
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x80, (byte) 0x45, (byte) 0x15, (byte) 0x54, (byte) 0x44, (byte) 0x44, (byte) 0x11,
            (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0xAA, (byte) 0x42, (byte) 0x08, (byte) 0x80, (byte) 0x00,
        };
        /////////////PARAMETERS FOR CCF ACK///////////////

        //************CREATING DATA_GET COMMAND************//
        EGNOS_Client Client = new EGNOS_Client();
        
        //************INIT XML************//
//        System.out.println("INIT XML");
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.newDocument();

        //************REDIRECT STD OUTPUT TO TXT FILE************//
        Client.initLog();
        
        //************READ FROM TXT FILE************//
        listIPAddr = Client.readIPFile();

        //************SEND & RECEIVE MULTIPLE************//
        
        System.out.println(Client.whatTimeIsIt());
        
        Client.writeColumnTitles();
        
        //XML
        Client.xmlInit(doc);

        for (int i = 0; i < listIPAddr.length; i++) {

            Client.resetStdOutput();
//            System.out.println("\nAUDITING " + listIPAddr[i] + "\n");
            
            
            Client.setLog();
            System.out.println();
            System.out.println("*************SENDING TO " + listIPAddr[i] + "*************");
            System.out.println();
            
            //If the asset is a FEE
            for (int j = 0; j < indexOfFEE.length; j++) {
                if (i == indexOfFEE[j]) {
                    Client.writeTime();
                    
                    //TIME XML
                    Client.xmlTime(doc);
                    
                    Client.resetStdOutput();
                    System.out.println(Client.whatTimeIsIt());
                    Client.setLog();
                    
                    if (count == 1){
                        //If there is only one asset to audit
                        Client.writeEGNOSAddr(egnosAddress);
                        //XML
                        Client.xmlEgnosAddr(doc, Integer.toString(egnosAddress));
                        Client.xmlAssetName(name, doc);
                        
                        Client.resetStdOutput();
                        System.out.println(name);
                        System.out.println(Integer.toString(FEESysContact));
                        System.out.println(egnosAddress);
                        Client.setLog();
                    }
                    else{
                        Client.writeEGNOSAddr(egnosAddresses[i]);
                        //XML
                        Client.xmlEgnosAddr(doc, Integer.toString(egnosAddresses[i]));
                        Client.xmlAssetName(names[i], doc);
                        
                        Client.resetStdOutput();
                        System.out.println(names[i]);
                        System.out.println(Integer.toString(FEESysContact));
                        System.out.println(egnosAddresses[i]);
                        Client.setLog();
                    }
                    
                    //Write in CSV and XML
                    Client.writeFEEVersion(Client.getFEESysContact(listIPAddr[i],doc),doc);
                    
                    Client.writeTime();
                    
                    //TIME XML
                    Client.xmlTime(doc);
                    
                    Client.resetStdOutput();
                    System.out.println(Client.whatTimeIsIt());
                    Client.setLog();
                    
                    if (count == 1){
                        //If there is only one asset to audit
                        Client.writeEGNOSAddr(egnosAddress);
                        //XML
                        Client.xmlEgnosAddr(doc, Integer.toString(egnosAddress));
                        Client.xmlAssetName(name, doc);
                        
                        Client.resetStdOutput();
                        System.out.println(name);
                        System.out.println(Integer.toString(FEESignSWVersion));
                        System.out.println(egnosAddress);
                        Client.setLog();
                    }
                    else{
                        Client.writeEGNOSAddr(egnosAddresses[i]);
                        //XML
                        Client.xmlEgnosAddr(doc, Integer.toString(egnosAddresses[i]));
                        Client.xmlAssetName(names[i], doc);
                        
                        Client.resetStdOutput();
                        System.out.println(names[i]);
                        System.out.println(Integer.toString(FEESignSWVersion));
                        System.out.println(egnosAddresses[i]);
                        Client.setLog();
                    }
                    
                    //Write in CSV and XML
                    Client.writeFEEVersion(Client.getFEESignSWVersion(listIPAddr[i],doc),doc);
                    
                    next = true;
                }
            }
            //Skip to next iteration
            if (next) {
                next = false;
                continue;
            }
            
            //If there is only one asset to audit
            if (count == 1) {
                listFileCode = Client.readFileCode(name);
                
                //If the EGNOS address is smaller than 255 (can be stored in 1 byte)
                if (egnosAddress < 0xFF)
                    destinationAddress = new byte[] {(byte)0x00,(byte)egnosAddress};
                //If the EGNOS address is bigger than 255 (cannot be stored in 1 byte)
                else
                    destinationAddress = BigInteger.valueOf(egnosAddress).toByteArray();
            }
            //If there are more than one to audit
            else {
                listFileCode = Client.readFileCode(names[i]);
                //If the EGNOS address is smaller than 255 (can be stored in 1 byte)
                if (egnosAddresses[i] < 0xFF)
                    destinationAddress = new byte[] {(byte)0x00,(byte)egnosAddresses[i]};
                //If the EGNOS address is bigger than 255 (cannot be stored in 1 byte)
                else
                    destinationAddress = BigInteger.valueOf(egnosAddresses[i]).toByteArray();
            }
            
            //If the asset is a CCF
            for (int j = 0; j < indexOfCCF.length; j++) {
                if (i == indexOfCCF[j]) {
                    for (int k = 0; k < listFileCode.length; k++) {
                        //CCF ACK
                        wholeMessage = Client.createMessageCCF_ACK("DATA_GET CCF ACK ", ACKmsgType, ACKflowType,
                                headerLength, originAddress, destinationAddress, spare,
                                ACKsectionIdentifier, ACKconfirmationKey, commandType, ACKcommandParameter);
                        System.out.println("SENDING CCF ACK");
                        Client.sendMessage(listIPAddr[i], wholeMessage, doc);
                        
                        //Actual DATA_GET
                        commandParameterCCF = listFileCode[k];
                        if (count == 1) {
                            System.out.println("SENDING CCF DATA_GET");
                            wholeMessage = Client.createMessageCCF("DATA_GET " + name + " " + listFileCode[k], msgType, flowType,
                                    headerLength, originAddress, destinationAddress, spare,
                                    sectionIdentifier, confirmationKey, commandType, commandParameterCCF);
                            Client.sendMessage(listIPAddr[i], wholeMessage, doc);
                        } else {
                            System.out.println("SENDING CCF DATA_GET");
                            wholeMessage = Client.createMessageCCF("DATA_GET " + names[i] + " " + listFileCode[k], msgType, flowType,
                                    headerLength, originAddress, destinationAddress, spare,
                                    sectionIdentifier, confirmationKey, commandType, commandParameterCCF);
                            Client.sendMessage(listIPAddr[i], wholeMessage, doc);
                        }
                    }
                    //Client.sendMessage(listIPAddr[i], wholeMessage);
                    next = true;
                }
            }
            //Skip to next iteration
            if (next) {
                next = false;
                continue;
            }
            
        
            //IF IT IS NOT A FEE OR CCF
            //Create a message and send it for each parameter of the asset
            for (int j = 0; j < listFileCode.length; j++) {
                
                    Client.resetStdOutput();
                    System.out.println(Client.whatTimeIsIt());
                    Client.setLog();
                    
                if (count == 1) {
                    //Detect if it's sending to an NLES (command parameter is different from other assets)
                    if (name.equals(nameNLESG2_2) || name.equals(nameNLES_2)) {
                        commandParameter = new byte[]{(byte) 0x00, (byte) listFileCode[j]};
                    } else {
                        commandParameter[1] = listFileCode[j];
                    }
                    wholeMessage = Client.createMessage(name, msgType, flowType, 
                        headerLength, originAddress, destinationAddress, spare,
                        sectionIdentifier, confirmationKey, commandType, commandParameter);
                    Client.resetStdOutput();
                    System.out.println(listFileCode[j]);
                    Client.setLog();
                }
                    
                else {
                    //Detect if it's sending to an NLES (command parameter is different from other assets)
                    if (names[i].equals(nameNLESG2_2) || names[i].equals(nameNLES_2)) {
                        commandParameter = new byte[]{(byte) 0x00, (byte) listFileCode[j]};
                    } else {
                        commandParameter[1] = listFileCode[j];
                    }
                    wholeMessage = Client.createMessage(names[i], msgType, flowType,
                            headerLength, originAddress, destinationAddress, spare,
                            sectionIdentifier, confirmationKey, commandType, commandParameter);
                    Client.resetStdOutput();
                    System.out.println(listFileCode[j]);
                    Client.setLog();
                }
                    
                
                Client.writeTime();
                //TIME XML
                Client.xmlTime(doc);
                
                
                if (count == 1) {
                    //Write EGNOS address
                    Client.writeEGNOSAddr(egnosAddress);
                    Client.xmlEgnosAddr(doc, Integer.toString(egnosAddress));
                    Client.xmlAssetName(name, doc);
                    
                    Client.xmlParameter(doc);
                    
                    //Write Parameter name and number
                    Client.writeFileCode(name,Client.hexToInt(commandParameter),doc,Integer.toString(egnosAddress));
                }
                    
                else {
                    //Write EGNOS address
                    Client.writeEGNOSAddr(egnosAddresses[i]);
                    Client.xmlEgnosAddr(doc, Integer.toString(egnosAddresses[i]));
                    Client.xmlAssetName(names[i], doc);
                    
                    
                    Client.xmlParameter(doc);
                    
                    //Write Parameter name and number
                    Client.writeFileCode(names[i],Client.hexToInt(commandParameter),doc,Integer.toString(egnosAddresses[i]));
                }


                Client.sendMessage(listIPAddr[i], wholeMessage, doc);
                
                //XML write version IF ASSET IS NOT RESPONDING
                if (socketTimeOut) {
                    socketTimeOut = false;
                    Client.xmlVersion(doc, "N/A TIMEOUT");
                }
                
                //XML write type (common or specific)
                Client.xmlType(doc);
                
                Client.writeLineSeparator();
            }
        }
        if (splitCounter != 0) {
            System.out.println("splitCounter = " + splitCounter);
            }
        

        //Reset the output to standard console output
//        Client.resetStdOutput();

        //XML write version IF COMMAND REJECTED
        if (rejectedCounter != 0) {
//            System.out.println("rejectedCounter = " + rejectedCounter);
            Client.xmlVersion(doc, "N/A REJECTED");
//            Client.resetStdOutput();
//            System.out.println("N/A REJECTED");
//            Client.setLog();
        }

        Client.setLog();
        System.out.println("\n*********\nAUDIT COMPLETED");
    }    
}

/*****************************************************************************
 * Class Name : getResponse
 * Purpose : Receive the message response from the asset and analyze it.
 * *************************************************************************/
class getResponse implements Runnable {
    
    public final String output = "output.csv";
    private final Socket socket;
    BufferedReader reader;
    byte[] data = new byte[1024];
    int data_length;
    InputStream stream ;
    int responseCounter = 2;
    int normalAnswer = 57;
    int dataRequested = 92;
    int dataRequested_NLES = 88;
    
    //XML
    Document doc;
    
    public getResponse(Socket s, Document d) throws IOException {
        socket=s;
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        stream = s.getInputStream();
        
        //XML
        doc = d;
    }

    /*****************************************************************************
     * Name : setLog
     * Purpose : Redirect the output to a log file
     * Argument I/O: 
     * I/O Files: No input file
     * Returns :
     * 
     * @throws java.io.FileNotFoundException *************************************************************************/
    public void setLog() throws FileNotFoundException {
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
    public void resetStdOutput() {
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
    }
    
    /*****************************************************************************
     * Name : reduceData
     * Purpose : Reduce the version number
     * Argument I/O: Byte array containing the version number
     * I/O Files: No input file
     * Returns : 
     * 
     * @param data
     * @return 
     * *************************************************************************/
    public byte[] reduceData(byte [] data) {
        
        int start = 4;
        int dataLength = 32;
        byte[] reduced = new byte[dataLength];
        
        System.arraycopy(data, start, reduced, 0, dataLength);
        
        return reduced;
    }
    
    /*****************************************************************************
     * Name : hexToAscii
     * Purpose : Convert hexadecimal version number to String and remove invalid characters in XML
     * Argument I/O: Hex Byte array containing the version number
     * I/O Files: No input file
     * Returns : 
     * 
     * @param data
     * @return
     * *************************************************************************/
    public String hexToAscii(byte [] data) throws UnsupportedEncodingException, FileNotFoundException {
        
        byte[] notInvalid = null;
        int invalidCounter = 0;
        
        //----------------------------1st approach : Replace 0x00 with 0x20 (space)
//        for (int i = 0; i<data.length ; i++){
//            if (data[i] == 0x00){
//                data[i] = 0x20;
//                invalidCounter++;
//            }
//        }
//        resetStdOutput();
//        System.out.println("Invalid characters removed: " + invalidCounter);
//        setLog();

        //----------------------------2nd approach : Cut the version number at 0x00
        //Get the index of the first encountered invalid char
        for (int i = 0; i<data.length ; i++){
            if (data[i] == 0x00){
                invalidCounter=i;
                break;
            }
        }
        
        //Declare a smaller byte array and copy only the valid part in it
        if (invalidCounter != 0){
            notInvalid = new byte[invalidCounter];
            System.arraycopy(data, 0, notInvalid, 0, invalidCounter);
        }
        
        //-----------
        String response2 = null;
        if (invalidCounter != 0)
            response2 = new String(notInvalid, "UTF-8");
        String response1 = new String(data, "UTF-8");
        
        
        if (invalidCounter != 0){
            return response2;
        }
        else{
            return response1;
        }
            
    }
    
    /*****************************************************************************
     * Name : writeVersion
     * Purpose : Write the version number in the output file
     * Argument I/O: String containing the version number
     * I/O Files: No input file
     * Returns : 
     * 
     * @param data
     * *************************************************************************/
    public void writeVersion(String data) {

        File file = new File(output);
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(data);
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }

    }
    
    /*****************************************************************************
     * Name : writeRejected
     * Purpose : Write "REJECTED" in the output file when a command is rejected
     * Argument I/O:
     * I/O Files: No input file
     * Returns : 
     * 
     * *************************************************************************/
    public void writeRejected() {

        String rejected = "REJECTED";
        File file = new File(output);
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(rejected);
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }

    }
    
    /*****************************************************************************
     * Name : writeLineSeparator
     * Purpose : Write a line separator in the output file
     * Argument I/O: 
     * I/O Files: No input file
     * Returns : 
     * 
     * *************************************************************************/
    public void writeLineSeparator() {
        File file = new File(output);
        try {
            try (FileWriter writer = new FileWriter(file, true)) {
                writer.write(System.lineSeparator());
                writer.flush();
                writer.close();
            }

        } catch (IOException ex) {
            System.out.println("Error while writing in the file");
        }
    }
    
    /*****************************************************************************
     * Name : xmlVersion
     * Purpose : Write version
     * Argument I/O: XML document and version
     * I/O Files: No input file
     * Returns :
     * 
     *  
     *************************************************************************/
    public String xmlVersion(Document doc, String version) throws TransformerException{
        
        EGNOS_Client.versionElement = doc.createElement("version");
        EGNOS_Client.paramElement.appendChild(EGNOS_Client.versionElement);
        
        //If no version is given by the asset
        if (version.equals(""))
            EGNOS_Client.versionElement.appendChild(doc.createTextNode("N/A"));
        else
            EGNOS_Client.versionElement.appendChild(doc.createTextNode(version));
        
        //Write in XML
        xmlWrite(doc);
        
        return version;
    }
    
    /*****************************************************************************
     * Name : xmlWrite
     * Purpose : Write eeverything in the XML file
     * Argument I/O: XML document
     * I/O Files: No input file
     * Returns :
     * 
     *  
     *************************************************************************/
    public void xmlWrite(Document doc) throws TransformerConfigurationException, TransformerException{
        //Write in XML
            TransformerFactory transFactory = TransformerFactory.newInstance();
            Transformer trans = transFactory.newTransformer();
            DOMSource src = new DOMSource(doc);
            StreamResult res = new StreamResult(new File(EGNOS_Client.xml));
            trans.transform(src, res);
    }
    
    /*****************************************************************************
     * Name : parseResponse
     * Purpose : Analyze the response message from the asset
     * Argument I/O: Byte array containing the message
     * I/O Files: No input file
     * Returns : 
     * 
     * @param data
     * *************************************************************************/
    public void parseResponse(byte[] data) throws UnsupportedEncodingException, FileNotFoundException, TransformerException {
        
        //Header
        byte msgType;
        byte flowType;
        byte[] headerLength = new byte[2];
        byte[] originAddress = new byte[2];
        byte[] destinationAddress = new byte[2];
        byte[] spare = new byte[4];
        int startVerNum = 0;
        int startMsgType = 1;
        int startFlowType = 2;
        int startDataLength = 3;
        int startHdrLength = 5;
        int startOrAddr = 7;
        int startDestAddr = 10;
        int startTimeStamp = 13;
        int startSpare = 19;
        int startCRC = 27;
        
        //Command
        byte sectionId;
        byte[] sectionLength = new byte[2];
        byte[] confirmKey = new byte[20];
        byte cmdId;
        byte ackType;
        byte ackValue;
        byte[] ackValueData = new byte[36];
        byte[] ackValueDataNLES = new byte[32];
        int startSectionId = 31;
        int startSectionLength = 32;
        int startConfirmKey = 34;
        int startCmdId = 54;
        int startAckType = 55;
        int startAckValue = 56;
        
        String version;
        String rejected = "REJECTED";
        
        
        String nameOfMsg;
        byte reject = 0x02;
        
        if(data_length == normalAnswer)
            nameOfMsg = "Response";
        else
            nameOfMsg = "Requested Data";
        
        
        boolean resp = true;
        //CHECK HERE IF THERE'S NO ERROR SINCE CCF COMMAND CHANGES
        EGNOS_Message response = new EGNOS_Message(nameOfMsg,false,false,resp);
        
        
        System.out.println("Data length: " + data_length);
        
        System.out.println("");
        
        //Header copy
        msgType = data[startMsgType];
        flowType = data[startFlowType];
        System.arraycopy(data, startHdrLength, headerLength, 0, headerLength.length);
        System.arraycopy(data, startOrAddr, originAddress, 0, originAddress.length);
        System.arraycopy(data, startDestAddr, destinationAddress, 0, destinationAddress.length);
        System.arraycopy(data, startSpare, spare, 0, spare.length);
        
        //Command copy
        sectionId = data[startSectionId];
        System.arraycopy(data, startSectionLength, sectionLength, 0, sectionLength.length);
        System.arraycopy(data, startConfirmKey, confirmKey, 0, confirmKey.length);
        cmdId = data[startCmdId];
        ackType = data[startAckType];
        
        
        response.EGNOS_Header = new EGNOS_StandardHeader(msgType, flowType, headerLength, originAddress, destinationAddress, spare);
        response.EGNOS_Header.versionNum = data[startVerNum];
        System.arraycopy(data, startDataLength, response.EGNOS_Header.dataLength, 0, response.EGNOS_Header.dataLength.length);
        System.arraycopy(data, startTimeStamp, response.EGNOS_Header.timeStamp, 0, response.EGNOS_Header.timeStamp.length);
        System.arraycopy(data, startCRC, response.EGNOS_Header.fullMessageCRC, 0, response.EGNOS_Header.fullMessageCRC.length);
        
//        response.EGNOS_Header.printHeader();
        int i = 0;
        //If the message is 57 bytes long (normal message answer)
        if (data_length == normalAnswer) {
            ackValue = data[startAckValue];
            response.EGNOS_Cmd_Resp = new EGNOS_Command_Response(sectionId, sectionLength, confirmKey, cmdId, ackType, ackValue);
            response.EGNOS_Cmd_Resp.printCmdResp();
            //If command rejected
            if (response.EGNOS_Cmd_Resp.acknowledgementType == reject) {
                System.out.println("COMMAND REJECTED");
                
                resetStdOutput();
                System.out.println("REJECTED");
                xmlVersion(doc, rejected);
                setLog();
                
                //EGNOS_Client.rejectedCounter++;
                writeRejected();
                responseCounter--;
            }
        }
        //If the message contains the requested data (92 or 88 bytes long) 
        else if (data_length == dataRequested || data_length == dataRequested_NLES) {
            System.arraycopy(data, startAckValue, ackValueData, 0, ackValueData.length);
            response.EGNOS_Cmd_Resp_Req_Data = new EGNOS_Command_Response_Requested_Data(sectionId, sectionLength, confirmKey, cmdId, ackType, ackValueData);
            response.EGNOS_Cmd_Resp_Req_Data.printCmdRespReqData();
            writeVersion(hexToAscii(reduceData(ackValueData)));

            //XML
            version = xmlVersion(doc, hexToAscii(reduceData(ackValueData)));
            resetStdOutput();
            System.out.println(version);
            setLog();
        }
    }
    
    /*****************************************************************************
     * Name : splitResponse
     * Purpose : Split the response in two byte arrays when both messages are concatenated (happens from time to time)
     * Argument I/O: Byte array containing the response message
     * I/O Files: No input file
     * Returns : 
     * 
     * @param data
     * *************************************************************************/
    public void splitResponse(byte [] data) throws UnsupportedEncodingException, FileNotFoundException, TransformerException {
        
        System.out.println("DATA TOO BIG (" + data_length + " bytes) --------------------------------------------------------- SPLITTING RESPONSE\n\n\n");
        
        byte[] small = new byte[normalAnswer];
        byte[] big = new byte[dataRequested];
        
        //Copy first part of the message (regular response) in a small byte array (57 bytes long)
        System.arraycopy(data, 0, small, 0, normalAnswer);
        for (int i = 0; i < small.length; i++) {
            System.out.printf("%02x ", small[i]);
        }
        System.out.println("");
        
        //Copy second part of the message (data requested) in a big byte array (92 bytes long)
        System.arraycopy(data, normalAnswer, big, 0, dataRequested);
        for (int i = 0; i < big.length; i++) {
            System.out.printf("%02x ", big[i]);
        }
        System.out.println("");
        
        //Parse both messages
        data_length = normalAnswer;
        parseResponse(small);
        data_length = dataRequested;
        parseResponse(big);
    }
    
    /*****************************************************************************
     * Name : run
     * Purpose : Thread for receiving the response message
     * Argument I/O: None  
     * I/O Files: No input file
     * Returns : 
     * .
     * *************************************************************************/
    @Override
    public void run() {
        
        try {

            while ( ((data_length = stream.read(data)) != -1)) {
                System.out.println();
                System.out.printf("Server: ");
                
                for (int k = 0; k < data_length; k++) {
                    System.out.printf("%02X ", data[k]);
                }
                System.out.println();
                System.out.println();
                
                //If data is too big (merger of two actual messages)
                if (data_length > dataRequested) {
                    splitResponse(data);
                    EGNOS_Client.splitCounter++;
                    responseCounter-=2;
                }    
                else {
                    parseResponse(data);
                    responseCounter--;
                }
                    
                Thread.sleep(1000); //Otherwise, the asset can fail (happens with RIMS A, didn't test on other assets)
                
                //We are expecting two answers from the asset
                if (responseCounter == 0) {
                    responseCounter = 2;
                    break;
                }
            }    
        } catch (IOException | InterruptedException | TransformerException ex) {
            Logger.getLogger(getResponse.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
