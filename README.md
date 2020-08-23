# IoT-app_PrivacyInspector
The objective of this tool is to help IoT user to investigate whether their IoT devices send personal identifiable information to its manufacturer's cloud


Code description: 
When you run the code, it will first ask you to specify the IoT type by selecting its correspondence number. Then you will provide the path of the pcap file that you want
to analyze, and the path of where you want to save your results. 
The first routine in this program is invoked (convertedCapturesToCsv). This routine is responsible for reading the pcap file and apply the ssl.app_data filter. 
This filter will allow us to not only filter the SSL traffic, but also to be more focus on the encrypted application data only, which in turn reflects the encrypted data
moving between the IoT-app and the IoT cloud. In addition, we identify which fields we want to extract from the pcap file namely; IP source, IP destination, source TCP port,
destination TCP port, source UDP port, destination UDP port, and packet size. Finally, we save the results in a tmp_features.csv file for later analysis. 
Next, the second routine is invoked (build_db). This routine takes three parameters; type of the IoT device, the tmp_features.csv file from the previous routine,
and the path where to save the results. Firstly, it will extract the relevant features from the tmp_features.csv file namely; IP source, IP destination, and packet length. 
Then, it will add another feature which is the communication type (comm_type) between the IoT-app and the IoT cloud. The new feature will be filled based on the IoT type. 
For example, if the IoT type is 1, then our IoT target is TP-link smart camera. This smart camera communicates with two clouds. So, if the source IP address belongs to 
the smart phone and the destination IP address is belonging to the first cloud, then 1.1 is assigned to the communication type and so forth if the destination IP address 
is belonging to the second cloud then the comm-type is 1.2. While if the IoT type is 4, then our IoT is LIFX smart lamb. LIFX communicate with 5 different clouds. 
We assign 4.1, 4.2, 4.3, 4.4, or 4.5 to the comm_type based on the source IP address and the destination IP address. Finally, the results will be saved in PhoneToCloud.csv file 
in the specified path. Notice that each record in the PhoneToCloud.csv file represent either send packet from the IoT-app installed in the smartphone to the IoT cloud or receive
packet from the IoT cloud to the IoT-app installed in the smartphone. Thus, our third routine (conversation) will run automatically after generated the PhoneToCloud.csv file 
to aggregate the send and the received packet that formulate one conversation. The results will be saved in PhoneToCloud_conversation.csv file in the same path with 
the PhoneToCloud.csv file. 
It is important to highlight that PhoneToCloud_conversation.csv file will be used as unseen data to analyze and infer if there is any personal sensitive data transferred to the 
cloud, as well as infer the type of user interaction with the IoT device.

Its worth to say that previously we only provide the two paths of pcap file and the place where to save your results without specifying the type of the IoT device. 
However, we faced a serious performance issue, because we have to look for the IP destination of each single packets in a pcap file, that could have millions of packets, 
through a list that contains all the IoT cloud’s domain names (12 IoT clouds). In this case the performance was totally damaged. 
Therefore, to optimize the performance we asked the user to specify the IoT type, so instead of looking among 12 different domain names, we could only look for a specific domain
name. for example, 2 domain names for TP-link smart camera. 

After that, the program will print a message to inform the user that the data set was successfully generated and ready to be analyzed. So, the program will ask the user 
if he wants to proceed to the analysis process. The result of this analysis will accurately tell the user the following:
1.	If there is any sensitive personal identifiable information being sent to the IoT cloud.
2.	What is/are this information.
3.	What is his interaction with the IoT-app; is it login, logout, delete, or change password
To achieve this goal, we used in our program three different machines learning each one of them used for different prediction. 
We applied supervised machine learning algorithm, Random Forest, to the three different machines learning. 
To train and evaluate multi-class classifiers, we collected network traffic data from 4 distinct IoT devices. 
First, we collected the encrypted and its corresponding decrypted traffic of each IoT device for 4 main user interaction, then we identify the size of the packets 
that carry sensitive information about the user and send it to the cloud, as well as the methods that reveal the interaction type between the user and the IoT-app. 
Second, we selected four features with the aim of accurately identifying; if the IoT device sends any personal identifiable information to the cloud; 
what is this sensitive information, and to accurately inferring the user interaction type with the IoT-app, then we manually labeled the network traffic data 
based on our finding into three main data set, each of which used to train and classify one classifier. 




