# IoTSeeker


   This scanner will scan different types of IoT devices to detect if they still have the default credentials on. The recent 
Internet outage was because of the IoT devices (IP Camera and such) with default password.   It's the intention of this tool
help organizations to scan and detect this type of IoTs. Note that the Miral software, the one responsible for massive internet outage on Oct 21, 2016, mainly focuses on telnet services,  IoTSeeker focuses on HTTP/HTTPS services.

Due to the potentially large number of IoT types and large IP ranges, this tool was designed with 

* High parallelism. So that it can scan thousands of IoT's at the same time
* Extensibility.  So one doesn't need to change lots of code to add the support for a new IoT.

The software has two parts. One is the device configuration file which is in JSON format,  the other is the scanner coded
in perl that does scanning, device identification and logging under the control the device configuration.

This software uses the perl module AnyEvent for high parallelism and as a result, it only runs on Linux or Mac OS.

Here are the steps to install and run it:

* make sure perl and cpan are installed.  
* Install perl packages by 
 * cpan AnyEvent::HTTP Data::Dumper JSON
* perl iotScanner.pl <ipRanges>
  * example:  perl iotScanner.pl 1.1.1.1-1.1.4.254,2.1.1.1-2.2.3.254
  
  

