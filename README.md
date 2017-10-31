# EGNOS-Audit-Tool
EGNOS automated audit tool developped in JAVA

Tool designed and implemented during Thales Alenia Space internship 2016-2017 with IDE NetBeans.

Automated tool recreating EGNOS command packets and sending them to the corresponding assets IP addresses.

The list of assets to audit is found in the ip_addresses.txt.
A complete list of all assets is given in IP + EGNOS ADDRESSES.txt.

Each asset has different file codes corresponding to different binary and EXE files installed. To each asset corresponds a .txt file in which are given the File Codes.
Ex: the file corresponding to RIMS A is named RIMSA.txt.

At the end of execution, the results of the audit will be given in audit.xml and output.csv. Beware, the writing of the results in the .csv file is from an old version of the tool and may not be working properly.
The audit.xml file can be used as an input for the EGNOS Comparison tool.
