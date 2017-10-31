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
public class CheckIPAddress {
    
    String IPAddress;
    
    public CheckIPAddress(String ip) {
        
    IPAddress = ip;
    
}
    
    public boolean checkValidity(){
//        String IPAddress = "199.34.191.1";
//        IPAddress = jTextField1.getText();
        boolean notValid = false;
        System.out.println("Checking IP Address " + IPAddress + "...");
        if(IsValid(IPAddress)){
            System.out.println(IPAddress + " is valid");
        }
        else {
            System.out.println(IPAddress + " is not valid");
            notValid = true;
        }
        return notValid;
    }
    
        public boolean IsValid(String IPAddress){

        boolean valid=false;
        String IfaceNewIP1;
        String IfaceNewIP2;
        String IfaceNewIP3;
        String IfaceNewIP4;
        
        //Check if it has at least one dot
        if (IPAddress.contains(".")) {
//            System.out.println(IPAddress);
            IfaceNewIP1 = IPAddress.substring(0, IPAddress.indexOf('.'));
            //Check first byte in range (cannot be 0 nor 255)
            if (Integer.parseInt(IfaceNewIP1) > 0 && Integer.parseInt(IfaceNewIP1) < 255) {

                IfaceNewIP2 = IPAddress.substring(IPAddress.indexOf('.') + 1, IPAddress.indexOf('.', IPAddress.indexOf('.') + 1));
                //Check second byte in range (cannot be 255)
                if (Integer.parseInt(IfaceNewIP2) >= 0 && Integer.parseInt(IfaceNewIP2) < 255) {

                    IfaceNewIP3 = IPAddress.substring(
                            IPAddress.indexOf('.', IPAddress.indexOf('.') + 1) + 1,
                            IPAddress.indexOf('.', IPAddress.indexOf('.', IPAddress.indexOf('.') + 1) + 1));

                    //Check Third byte in range (cannot be 255)
                    if (Integer.parseInt(IfaceNewIP3) >= 0 && Integer.parseInt(IfaceNewIP3) < 255) {

                        IfaceNewIP4 = IPAddress.substring(
                                IPAddress.indexOf('.', IPAddress.indexOf('.', IPAddress.indexOf('.') + 1) + 1) + 1,
                                IPAddress.length());
                        //Check fourth byte in range (cannot be 0 nor 255)
                        if (Integer.parseInt(IfaceNewIP4) > 0 && Integer.parseInt(IfaceNewIP4) < 255) {

                            valid = true;
                        }
                    }

                }

            }

        }
        
        return valid;
    }
    
}
