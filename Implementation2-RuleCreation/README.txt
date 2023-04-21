
##CoAP Profiling using Python 

##Introduction

##This project is designed to profile CoAP (Constrained Application Protocol) traffic using Python.It reads in pcap file and uses Pyshark to extract information about CoAP messages.It then applies a set of rules to the CoAP messages in order to identify patterens or anomilies in the traffic.

Install required dependencies

pip install pyshark

##Usage

##1) Start running the coap_rule.py script by 
	python3 coap_rule.py [pcap_File] [IP_Addr(optional)] [SRC_Port(optional)]

##Here IP_Addr and SRC_Addr is optional for getting particular rules for specific IP_Address and SRC_Port

##2) The script will read in the pcap file and extract CoAP messages using Pyshark. It will then apply a set of rules to the CoAP messages and write the results to the output file 

##3) You can also modify the coap_rule.py script to change the output format or add additional processing steps.
