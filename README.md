# mtp2019
An Open-Source Simulation Environment for IoT Devices 

Objective : 
To Develop an Open Source Simulation Environment for IOT Devices with Key Management, Credential Management and Trust Score Calculation Features. 

Experimental Setup : 
The  setup  involves  three  virtual  machines,  one  machine  with  Ubuntu  operating  system  running  the  webserver and the  two  other  machines  with  Debian operating system running the agent code.  The dashboard web application is developed in Django. The agent code is developed in python3.

Brief Overview :
In Credential Management feature, credentials are sent to target device which are then stored in a JSON file similar to as in WoTT. Web application in the device makes use of these credentials for authentication. In Key Management feature, X.509 certificate and private key file are generated. They are used for secure message communication using a session key which is secretly exchanged between the devices. For Trust Score calculation, parameters are collected from the device. Feedback parameters given by other devices are also sent to the centralised server. Dynamic weighted average model is applied on the trust values derived from these parameters to get the trust score of the device in percentage.



References :

[1] ”WoTT Agent Source”, https://github.com/WoTTsecurity/agent, Web Of
Secure Things Ltd, 2019, Accessed on: November 26, 2019.<br />
[2] ”WoTT Usecase”, https://wott.io/blog/tutorials/2019/06/18/simple-webapp-auth, Web of Secure Things Ltd, 2019, Accessed on:
November 26, 2019.<br />
[3] Ayesha Altaf Et Al. ”Trust models of internet of smart things: A survey,
open issues, and future directions”. Journal of Network and Computer
Applications, 2019.<br />
[4] N. B. Truong Et Al. ”A survey on trust computation in the internet
of things”. The Journal of Korean Institute of Communications and
Information Sciences (JKICS), 2016.<br />
[5] Y. Yu Et Al. ”An efficient trust evaluation scheme for node behavior
detection in the internet of things”. Wireless Personal Communications:
An International Journal, 2015.<br />
[6] ”WoTT Documentation”, https://wott.io/documentation/getting-started,
Web Of Secure Things Ltd, 2019, Accessed on: November 26, 2019.<br />
[7] Cedric Adjih Et Al. ”FIT Iot-Lab: A Large Scale Open Experimental Iot
Testbed”. In IEEE 2nd World Forum on Internet of Things (WF-IoT),
pages 1–3, December 2015.<br />
[8] Rwan Mahmoud Et Al. ”Internet of things (IoT) security: Current status,
challenges and prospective measures”. In 10th International Conference
for Internet Technology and Secured Transactions (ICITST), pages 2–3,
December 2015.<br />
[9] Fenye Bao Et Al. ”Dynamic Trust Management for Internet of Things
Applications”. In International Conference on Autonomic Computing
and Communications Conference(ICAC), 2012.<br />
[10] O. B. Abderrahim Et Al. ”Ctms-siot: A context based trust management
system for the social internet of things”. In 13th International Wireless
Communications and Mobile Computing Conference (IWCMC), 2017.<br />
