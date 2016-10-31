# IoTSeeker


   This scanner will scan a network for specific types of IoT devices to detect if they are using the default, factory set credentials. The recent Internet outage has been attributed to use the IoT devices (CCTV Cameras, DVRs and others) with default credentials. It's the intention of this tool to help organizations scan their networks to detect these types of IoT devices and to identify whether credentials have been changed or if the device is still using the factory setting. Note that Mirai malware, suspected to have been used to launch the massive internet outage on Oct 21, 2016, mainly focuses on telnet services. IoTSeeker focuses on HTTP/HTTPS services.


   In order to accommodate large IP ranges and make it capable of finding a large number of different types of IoT devices, this tool was designed with:


* High parallelism. So that it can scan thousands of IoT's at the same time
* Extensibility, making it easy to support new types of devices without needing to change or write lots of code.


The software has two parts. One is the device configuration file which is in JSON format,  the other is the scanner, coded
in perl, that does scanning, device identification and logging under the control the device configuration file.

This software uses the perl module AnyEvent for high parallelism and as a result, it only runs on Linux or Mac OS.

Here are the steps to install and run it:

* make sure perl and cpan are installed.  
* Install perl packages by 
 * cpan AnyEvent::HTTP Data::Dumper JSON
* perl iotScanner.pl <ipRanges>
  * example:  perl iotScanner.pl 1.1.1.1-1.1.4.254,2.1.1.1-2.2.3.254
  
  

