# ciscomultiosinfocoordinate

## Written By: Benjamin P. Trachtenberg 

### Contact Information:  e_ben_75-python@yahoo.com

### LinkedIn: [Ben Trachtenberg](https://www.linkedin.com/in/ben-trachtenberg-3a78496)

### Requirements

* [ipaddresstools](https://github.com/btr1975/ipaddresstools)
* [persistentdatatools](https://github.com/btr1975/persistentdatatools)

### About

This is a library that can take IOS, IOS-XE, IOS-XR, and NX-OS data and give it a common format.

### Features
1. CiscoTelnetClass
    * Supports IOS, IOS-XE, IOS-XR, and NX-OS
        * Can Pull the Following
            * Running Configuration
            * CEF Table
            * Mroute Table
            * BGP Table
            * MAC Address Table
            * ARP Table
    
2. CiscoInfoNormalizer
    * Supports IOS, IOS-XE, IOS-XR, and NX-OS
        * Creates Dictionaries from the Following
            * Running Configuration
            * CEF Table
            * Mroute Table
            * BGP Table
            * MAC Address Table
            * ARP Table
        
3. CiscoInfoCorrelater
    * Supports IOS, IOS-XE, IOS-XR, and NX-OS
        * Matches Mroutes to Source Interfaces in a List