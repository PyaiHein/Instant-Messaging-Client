#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <iostream>
#include <signal.h>
#include <fstream>
#include <sys/stat.h>
#include <fcntl.h>
#include <poll.h>
#include <string>
#include <dirent.h>
#include <vector>
#include <queue>
#include <netdb.h>
#include <termios.h>
#include <sys/uio.h>
#include <ostream>
#include <math.h>
#include <sstream>
#include <time.h>
#include <inttypes.h>

#include "EncryptionLibrary.h"


using namespace std;
#define BUFFER_SIZE 256

uint32_t tcpport = 50551;
uint32_t udpport = 50550;
uint32_t anchorport = 50552;
struct pollfd mysock;
vector <pollfd> allpoll;
int sockfd, tcpsock, tcpfd, Newtcp, anchorfd;
char myinfoBuf[BUFFER_SIZE];
char mydataBuf[BUFFER_SIZE];
char myanchorBuf[BUFFER_SIZE];
int sendsize = 0;
int udpsendsize = 0;
int anchorsendsize = 0;
struct sockaddr_in ServerAddress, sa, ca, ta, to, tcpAddress, ClientAddress, anchorAddr;
socklen_t ca_len;
struct iovec mainiov[50];
struct hostent *Server;
char userInput;
int passConf = 0;
int wowcount = 0;

struct termios restore;

void restore_can ()  // need to restore to old attributes of shell
{
    tcsetattr (STDIN_FILENO, TCSANOW, &restore);
}

void set_can ()
{
    struct termios input;
    tcgetattr (STDIN_FILENO, &restore);   //save restore attributes for restore
    tcgetattr (STDIN_FILENO, &input);    //get terminal attributes
    input.c_lflag &= ~(ICANON|ECHO);    //change attribute
    input.c_cc[VMIN] = 1;
    input.c_cc[VTIME] = 0;
    tcsetattr (STDIN_FILENO, TCSAFLUSH, &input); //set non canonical mode
}

class clients
{
	public:
	int fdid;
	char host_name[50];
	char user_name[50];
	uint32_t udp_port;
	uint32_t tcp_port;
	int fd;
	int connected;
	int entryCount;
	int entryCounter;
	int encrypted;
	int authenticated;
	uint64_t sequenceNum;
	struct iovec iov[30];
};

vector <clients*> clientList;


void error(const char *message){
    perror(message);
    exit(0);
}

void signalHandler(int signum)
{
	char confirm[3];
	write(1,"Do you want to terminate? (y/n)\n",33);
	read (STDIN_FILENO, &userInput, 1);
	write (1, &userInput, 1);
	write (1, "\n", 1);

	userInput = tolower(userInput);

	if (userInput =='y')
	{
		*(myinfoBuf + 5) = 3;
	        	if(sendto(sockfd, myinfoBuf, udpsendsize, 0, (struct sockaddr *)&ca, ca_len) < 0)
		    	{
		        	error("ERROR sending to server");
		    	}


		close(sockfd);
		exit(signum);
	}
	else
		cout << endl;
}

uint64_t ntohll(uint64_t val){
    if(ntohl(0xAAAA5555) == 0xAAAA5555){
        return val;
    }
    return (((uint64_t)ntohl((uint32_t)(val & 0xFFFFFFFFULL)))<<32) | (ntohl((uint32_t)(val>>32)));
}

uint64_t htonll(uint64_t val){
    if(htonl(0xAAAA5555) == 0xAAAA5555){
        return val;
    }
    return (((uint64_t)htonl((uint32_t)(val & 0xFFFFFFFFULL)))<<32) | (htonl((uint32_t)(val>>32)));
}

void timeout_broadcast(int *timeout, int *time_out, int *timefirst, int maxtime, int selfdiscover)
{

		if(*time_out == 1)
		{
			*time_out = *timeout;
			*timefirst = 0;
		}

		if((clientList.size() == 0) && (selfdiscover==0) )/*&& (passConf==1) ) && (fromanchor == 0))*/
		{

			*(myinfoBuf + 5) = 1;
			cout << "timeout_braodcast sendto" << endl;
		    if(sendto(sockfd, myinfoBuf, udpsendsize, 0, (struct sockaddr *)&ServerAddress, sizeof(ServerAddress)) < 0)
		    {
		        error("ERROR sending to server");
		    }
		    else
		    {
		    	//cout << "Sending discovery, timeout = " << time_out/1000 <<  "s" << endl;
			    if(*timefirst)
			    {
			    	if((*(time_out) * 2) > maxtime)
			    		*(time_out) = maxtime;
			    	else
			    		*(time_out) *= 2;
			    }
			    else
			    {
			    	*timefirst = 1;
			    }
			    cout << "Sending discovery, timeout = " << *(time_out)/1000 <<  "s" << endl;

		    }
		}

}


int main(int argc, char* argv[])
{ 
	int broadcast = 1;
	socklen_t ClientLength;
    char recbuffer[BUFFER_SIZE];

    char user[100]= "\0";
    char host[100]= "\0";
    char tmphost[100];
    char serv[100];

    int pollret;
    int timeout = 5000;
    int maxtime = 60000;
    int time_out = 1;
    int timefirst;
    int numcmp;

    int out;
    int k, j, n, m, i;
    int cancel;

    uint16_t value;
    char lo, hi;
    int hold;
    int entryCount = 0;
	string s;

	gethostname(host, 100);
	getlogin_r(user, 100);

	/****part 3 *****/
	srand (time(NULL));

	uint64_t random = GenerateRandomValue() & 0xFFFFFFFF;
	uint64_t nkey = 0; //= 3236135497857185447;
	uint64_t ekey = 0; //= 5;
	uint64_t dkey = 0; //= 2588908395385365581;
	uint64_t data = 0;
	uint64_t datalow = 0;
	uint64_t datahigh = 0;
	string upstring = user;
	upstring.append(":");

	int encrypt = 0;
	/***************/

	for(int c = 1; c < argc; c++)
	{
		if(strcmp(argv[c],"-u") == 0)
		{
			strcpy(user,argv[c+1]);
		}
		if(strcmp(argv[c],"-up") == 0)
		{
			udpport = atoi(argv[c+1]);
		}
		if(strcmp(argv[c],"-tp") == 0)
		{
			tcpport = atoi(argv[c+1]);
		}
		if(strcmp(argv[c],"-dt") == 0)
		{
			timeout = (atoi(argv[c+1])) * 1000;
		}
		if(strcmp(argv[c],"-dm") == 0)
		{
			maxtime = (atoi(argv[c+1])) * 1000;
		}
		if(strcmp(argv[c],"-pp") == 0)
		{
			
		}
	}
	set_can();

	string msg = host + '\0';
    string mssg = user + '\0';
 
/*************************************************************************************************************/
	cout << "Please Enter Password: " << endl;
	while(userInput != '\n')
	{
		read (STDIN_FILENO, &userInput, 1);
		if(userInput != '\n')
		{
			write(1, "*", 1);
			upstring.append(string(1,userInput));
		}
		else write(1, "\n", 1);
	}

	StringToPublicNED(upstring.c_str(), nkey, ekey, dkey);

	PublicEncryptDecrypt(random, P2PI_TRUST_E , P2PI_TRUST_N);

	data = htonll(random);

	bzero((char *) &anchorAddr, sizeof(anchorAddr));
    anchorAddr.sin_family = AF_INET;
    anchorAddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    anchorAddr.sin_port = htons(anchorport);

    bzero(myanchorBuf, BUFFER_SIZE);
    *(myanchorBuf + 0) = 'P';
    *(myanchorBuf + 1) = '2';
    *(myanchorBuf + 2) = 'P';
    *(myanchorBuf + 3) = 'I';

    *(myanchorBuf + 5) = 0x10;

    *(uint64_t*)(myanchorBuf + 6) = data;

    strcpy((myanchorBuf+14),(char*)mssg.c_str());
    anchorsendsize = 15 + (strlen((char*)mssg.c_str()));

/*****************************************************************************************************************/


/*****************************************************************************************/


/**********************************************************************************************************/

    sockfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    anchorfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	tcpsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	tcpfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if(setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0)
    {
        error("ERROR setting socket option");
        close(sockfd);
        return 1;
    }
    setsockopt(anchorfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    //trust anchor broadcast
    //sendto(sockfd, myanchorBuf, anchorsendsize, 0, (struct sockaddr *)&anchorAddr, sizeof(anchorAddr));

    signal(SIGTERM, signalHandler);
    signal(SIGINT, signalHandler);
    signal(SIGUSR1, signalHandler);
    
    bzero((char *) &ServerAddress, sizeof(ServerAddress));
    ServerAddress.sin_family = AF_INET;
    ServerAddress.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    ServerAddress.sin_port = htons(udpport);

    sa.sin_family = AF_INET;
    sa.sin_port   = htons(udpport);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
        cout << "Failed to start UDP server on port " << udpport << endl;
        return 1;
	}
	bind(anchorfd, (struct sockaddr *)&sa, sizeof(sa));

    bzero((char *) &tcpAddress, sizeof(tcpAddress));
    tcpAddress.sin_family = AF_INET;
    tcpAddress.sin_addr.s_addr = INADDR_ANY;
    tcpAddress.sin_port = htons(tcpport);
    if(bind(tcpsock, (struct sockaddr *)&tcpAddress, sizeof(tcpAddress)) < 0)
	{
        cout << "Failed to start TCP server on port " << tcpport << endl;
        return 1;
	}

	bzero((char *) &to, sizeof(to));
	to.sin_family = AF_INET;

	ClientLength = sizeof(ClientAddress);

	listen(tcpsock, 5);


    mysock.fd = sockfd;   //UDP
    mysock.events = POLLIN;  
    allpoll.push_back(mysock); 

    mysock.fd = tcpsock;			//TCP
    allpoll.push_back(mysock);  

    mysock.fd = STDIN_FILENO;     //input
    allpoll.push_back(mysock);



    int selfdiscover = 0;
    int tmpsize = 0;

	bzero(myinfoBuf, BUFFER_SIZE);
    *(myinfoBuf + 0) = 'P';
    *(myinfoBuf + 1) = '2';
    *(myinfoBuf + 2) = 'P';
    *(myinfoBuf + 3) = 'I';
    *(myinfoBuf + 4) = 0;
    *(myinfoBuf + 5) = 1;
    *(myinfoBuf + 6) = udpport >> 8;
    *(myinfoBuf + 7) = udpport >> 0;
    *(myinfoBuf + 8) = tcpport >> 8;
    *(myinfoBuf + 9) = tcpport >> 0;

    bzero(mydataBuf, BUFFER_SIZE);
    *(mydataBuf + 0) = 'P';
    *(mydataBuf + 1) = '2';
    *(mydataBuf + 2) = 'P';
    *(mydataBuf + 3) = 'I';

    string message = "";
    strcpy((myinfoBuf+10),(char*)msg.c_str());
    udpsendsize = 10 + (strlen((char*)msg.c_str())) + 1;
    strcpy((myinfoBuf+ udpsendsize),(char*)mssg.c_str());
    udpsendsize += (strlen((char*)mssg.c_str())) + 1;

    cout << "Username = " << user << endl;
    cout << "Hostname = " << host << endl;
    cout << "UDP Port = " << udpport << endl;
    cout << "TCP Port = " << tcpport <<endl;
    cout << "Mintimeout = " << timeout << endl;
    cout << "Maxtimeout = " << maxtime <<endl;

/*****************************************************************************************/
	cout << "Sending achor discovery" << endl;
	sendto(anchorfd, myanchorBuf, anchorsendsize, 0, (struct sockaddr *)&anchorAddr, sizeof(anchorAddr));

	recvfrom(anchorfd, recbuffer, BUFFER_SIZE, 0, (struct sockaddr *)&ca, &ca_len);
	if((ntohs(*(uint16_t*)(recbuffer + 4))) == 0x0011 && passConf == 0)
	{
		cout << "received authentication key reply message" << endl;
		i = 15 + strlen(recbuffer+14);
		if(ekey == ntohll(*(uint64_t*)(recbuffer + i)))
		{
			i += 8;
			if(nkey == ntohll(*(uint64_t*)(recbuffer + i)))
    		{
    			passConf = 1;
    			cout << "User/Pass authenticated!" << endl;
    		}
    		else
    			cout << "User/Pass Incorrect!" << endl;
		}
		else
			cout << "User/Pass Incorrect!" << endl;

	}
/*****************************************************************************************/

	while(1)
	{	
		ca_len = sizeof(ca);
		selfdiscover = 0;

		pollret = poll(allpoll.data(), allpoll.size(), time_out);
		if(pollret>0)
        {

			//recvfrom(tcpsock, recbuffer, BUFFER_SIZE, 0, (struct sockaddr *)&ca, &ca_len) < 0)
		
        	//cout << "poll ret is " << pollret << endl;
        	if(allpoll[0].revents & POLLIN)
        	{
				if(recvfrom(sockfd, recbuffer, BUFFER_SIZE, 0, (struct sockaddr *)&ca, &ca_len) < 0)
		        {
		            cout << "error receiving from client" << endl;
		        }		
		        //cout << ntohs(*(uint16_t*)(recbuffer + 4)) << (recbuffer+10)<< endl;
		        tmpsize = strlen(recbuffer+10) + 11;

		        //cout << " checking " << (ntohs(*(uint16_t*)(recbuffer + 4))) << endl;

		        //cout << "buffer 4 type is " << ntohs(*(uint16_t*)(recbuffer + 4)) << endl;
		        if((ntohs(*(uint16_t*)(recbuffer + 4))) == 1 
		        	&& (strcmp((recbuffer+10),host) == 0)
		        	&& (strcmp((recbuffer+tmpsize),user) == 0))
		        {

		        	cout << "Received self discover" << endl;
		        	selfdiscover = 1;
		      
		        }
		        else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 1 )
		        {
		        	clients* newClient = new clients;
		        	strcpy(newClient->host_name,(recbuffer+10));
		        	strcpy(newClient->user_name,(recbuffer+tmpsize));
		        	newClient->udp_port	= (ntohs(*(uint16_t*)(recbuffer + 6)));
		        	newClient->tcp_port = (ntohs(*(uint16_t*)(recbuffer + 8)));
		        	newClient->encrypted = 0;
		        	clientList.push_back(newClient);

		        	cout << "Received Discover from " << newClient->user_name << "@"
		        	<< newClient->host_name << " on UDP " << newClient->udp_port
		        	<< ", TCP " << newClient->tcp_port << endl;

		        	*(myinfoBuf + 5) = 2;
		        	if(sendto(sockfd, myinfoBuf, udpsendsize, 0, (struct sockaddr *)&ca, ca_len) < 0)
			    	{
			        	error("ERROR sending to server");
			    	}
			    	time_out = 1;
			    	selfdiscover = 0;
			  
		        }
		        else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 2)
		        {
		        	clients* newClient = new clients;
		        	strcpy(newClient->host_name,(recbuffer+10));
		        	strcpy(newClient->user_name,(recbuffer+tmpsize));
		        	newClient->udp_port	= (ntohs(*(uint16_t*)(recbuffer + 6)));
		        	newClient->tcp_port = (ntohs(*(uint16_t*)(recbuffer + 8)));
		        	clientList.push_back(newClient);

		        	cout << "Received reply from " << newClient->user_name << "@"
		        	<< newClient->host_name << " on UDP " << newClient->udp_port
		        	<< ", TCP " << newClient->tcp_port << endl;
		        	selfdiscover = 0;
		        	time_out = 1;
		        	
		        }
		        else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 3)
		        {
		       
		        	cout << "Received closing from " << (recbuffer+tmpsize) << "@"
		        	<< (recbuffer+10) << " on UDP " << (ntohs(*(uint16_t*)(recbuffer + 6)))
		        	<< ", TCP " << (ntohs(*(uint16_t*)(recbuffer + 8))) << endl;

		        	for(i = 0; i < clientList.size(); i++)
		        	{
		        		if((strcmp((recbuffer+10),clientList[i]->host_name) == 0)
		        		&& (strcmp((recbuffer+tmpsize),clientList[i]->user_name) == 0)
		        		&& (ntohs(*(uint16_t*)(recbuffer + 6)) == clientList[i]->udp_port)
		        		&& (ntohs(*(uint16_t*)(recbuffer + 8)) == clientList[i]->tcp_port))
		        		{
		        			if(clientList[i]->connected == 1)
		        				allpoll.erase(allpoll.begin()+clientList[i]->fdid);
		        			clientList.erase(clientList.begin()+i);
		        		}
		        	}
	        		if(clientList.size() == 0)
	        		{
	        			cout << "No clients, resetting timeout to 5" <<endl;
	        			time_out = 1;
	        		}
	        	}
	        	
			}
			else if(allpoll[1].revents & POLLIN)
			{
				ClientLength = sizeof(ClientAddress);
				Newtcp = accept(tcpsock, (struct sockaddr *)&ClientAddress, &ClientLength);

		        bzero(recbuffer, BUFFER_SIZE);
		        read(Newtcp,recbuffer,BUFFER_SIZE-1);

		        ClientAddress.sin_family = AF_INET;
				getnameinfo((struct sockaddr *)&ClientAddress, sizeof(ClientAddress), tmphost, sizeof(tmphost),serv,sizeof(serv),NI_NAMEREQD);

				numcmp = strlen(recbuffer+6);

				for(k = 0; k < clientList.size(); k++)
				{
					if(strncmp(clientList[k]->user_name,recbuffer+6,numcmp) == 0 
						&& strncmp(clientList[k]->host_name,tmphost,strlen(tmphost)) == 0)
					{
						clientList[k]->fd = Newtcp;
						clientList[k]->fdid = allpoll.size();
						mysock.fd = Newtcp;
						allpoll.push_back(mysock);
						break;
					}
				}

				if((ntohs(*(uint16_t*)(recbuffer + 4))) == 4)
				{
					cout << "Would you like to connect to " << (recbuffer + 6) << "@" << tmphost<<"? (y/n)" << endl;
					//clientList[k]->encrypted = 0;
					clientList[k]->authenticated = 0;

					read (STDIN_FILENO, &userInput, 1);
					
					if(userInput == 'y')
					{
						cout << "Connection established" << endl;
						clientList[k]->connected = 1;
						*(mydataBuf + 5) = 5;
						write(clientList[k]->fd, mydataBuf, 6);
					}
					else
					{
						cout << "Connection rejected" << endl;
						*(mydataBuf + 5) = 6;
						write(clientList[k]->fd, mydataBuf, 6);
						close(clientList[k]->fd);
					}
				}
				else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 0x00B)
				{
					cout << "Would you like to accept encrypted connection to " << (recbuffer + 6) << "@" << tmphost<<"? (y/n)" << endl;
					clientList[k]->authenticated = 0;

					j = 6 + strlen(recbuffer + 5);
					i = j + 8;

					read (STDIN_FILENO, &userInput, 1);
						
					if(userInput == 'y')
					{
						cout << "Encrypted Connection established" << endl;
						clientList[k]->encrypted = 1;
						*(mydataBuf + 5) = 0x0C;

						random = GenerateRandomValue();
						cout << random << endl;
						clientList[k]->sequenceNum = random;

						data = random & 0xFFFFFFFF00000000;
						data = data >> 32;
						
						PublicEncryptDecrypt(data, ntohll(*(uint64_t*)(recbuffer + j)), ntohll(*(uint64_t*)(recbuffer + i)));
						
						data = htonll(data);
						*(uint64_t*)(mydataBuf + 7) = data;

						data = random & 0x00000000FFFFFFFF;
						
						PublicEncryptDecrypt(data, ntohll(*(uint64_t*)(recbuffer + j)), ntohll(*(uint64_t*)(recbuffer + i)));
						
						data = htonll(data);
						*(uint64_t*)(mydataBuf + 15) = data;

						write(clientList[k]->fd, mydataBuf, 23);
					}
					else
					{
						cout << "Connection rejected" << endl;
						*(mydataBuf + 5) = 6;
						write(clientList[k]->fd, mydataBuf, 6);
						close(clientList[k]->fd);
					}
				}
				
				
			}
			else if(allpoll[2].revents & POLLIN)
			{
				selfdiscover = 1;
				//cout << "in mysock 2" << endl;
				read (STDIN_FILENO, &userInput, 1);
				//write (1, &userInput, 1);
				if(userInput == '?')
				{
					
				}
				else if(userInput == 'l')
				{
					cout << endl << "Your list of clients are..." << endl;
					for(j = 0; j < clientList.size(); j++)
					{
						cout << "UDP port: " << clientList[j]->udp_port
						<< "  TCP port: " << clientList[j]->tcp_port
						<< " " << clientList[j]->user_name << "@" 
						<< clientList[j]->host_name << endl;
					}
				}
				else if(userInput == 't')
				{
					if(clientList.size() != 0)
					{
						cout << endl << "Request connection from: (0,1,2,3...) or q to cancel " << endl;
						for(j = 0; j < clientList.size(); j++)
						{
								cout << j << ")  UDP port: " << clientList[j]->udp_port
								<< "  TCP port: " << clientList[j]->tcp_port
								<<  " " << clientList[j]->user_name << "@" 
								<< clientList[j]->host_name << endl;
						}
						read (STDIN_FILENO, &userInput, 1);
						//write (1, &userInput, 1);
						cancel = 0;
						if(userInput != 'q')
						{
							while(!(userInput-'0' >= 0 && userInput-'0' < clientList.size()))
							{
								cout << endl << "invalid choice" << endl;
								read (STDIN_FILENO, &userInput, 1);
								write (1, &userInput, 1);
								if(userInput == 'q')
								{
									cancel = 1;
									break;
								}
							}
							if (cancel == 0)
							{
								j = userInput-'0';
								bzero(mydataBuf, BUFFER_SIZE);
							    *(mydataBuf + 0) = 'P';
							    *(mydataBuf + 1) = '2';
							    *(mydataBuf + 2) = 'P';
							    *(mydataBuf + 3) = 'I';

								if(encrypt == 1)
								{
									*(mydataBuf + 5) = 0x0D;
									*(uint16_t*)(myanchorBuf) = 0x5555;
									string message = user + '\0';
								    strcpy((myanchorBuf+2),(char*)message.c_str());
								    cout << myanchorBuf << endl;
								    PrivateEncryptDecrypt((uint8_t*)myanchorBuf, (strlen((char*)message.c_str()))+2 , clientList[j]->sequenceNum);

								    sendsize = 6 + (strlen((char*)message.c_str())) + 2;
							    	strcpy((mydataBuf+6),myanchorBuf);

								    clientList[j]->connected = 1;
								    write(clientList[j]->fd, mydataBuf, sendsize);
								}
								else
								{
									*(mydataBuf + 5) = 4;
									string message = user + '\0';
								    strcpy((mydataBuf+6),(char*)message.c_str());
								    sendsize = 6 + (strlen((char*)message.c_str())) + 1;
								    clientList[j]->connected = 1;

								    Server = gethostbyname(clientList[(userInput-'0')]->host_name);
								    bcopy((char *)Server->h_addr, (char *)&to.sin_addr.s_addr, Server->h_length);
								    to.sin_port = htons(clientList[(userInput-'0')]->tcp_port);

								    clientList[j]->fd = tcpfd;
									clientList[j]->fdid = allpoll.size();
									mysock.fd = tcpfd;
									allpoll.push_back(mysock);

							        if(0 > connect(tcpfd, (struct sockaddr *)&to, sizeof(to)))
							        {
				    					error("ERROR connecting");
				    				}
									write(tcpfd, mydataBuf, sendsize);
								}
							}
						}
					}
					else
						cout << endl << "There are no clients to connect to" << endl;
				}
				else if(userInput == 'y')
				{
					cout << "Select a Connected Client. (q to exit)" << endl;
					for(j = 0; j < clientList.size(); j++)
					{
						if(clientList[j]->connected == 1)
						{
							cout << j << ")  UDP port: " << clientList[j]->udp_port
							<< "  TCP port: " << clientList[j]->tcp_port
							<<  " " << clientList[j]->user_name << "@" 
							<< clientList[j]->host_name << endl;
							if(clientList[j]->encrypted == 1)
							{
								cout << "encrypted, " << flush;
							} 
							else
							{
								cout << "not encrypted, " << flush;
							}
							if(clientList[j]->authenticated == 1)
							{
								cout << "authenticated" << flush;
							} 
							else
							{
								cout << "not authenticated" << flush;
							}
						}
					}
					read (STDIN_FILENO, &userInput, 1);
						
					j = userInput - '0';
					cout << clientList[j]->user_name << "@" 
					<< clientList[j]->host_name << endl <<
					"i to send message, u to request userlist" << endl;

					read (STDIN_FILENO, &userInput, 1);

					if(userInput == 'i')
					{
						cout << "(esc to exit chat)" << endl; 
						out = 0;
						do
						{
							message = "";
						
							write(1, clientList[j]->user_name, strlen(clientList[j]->user_name));
							write(1,"@",1); 
							write(1, clientList[j]->host_name, strlen(clientList[j]->host_name));
							write(1, "<< ", 3);
							do
							{
								read (STDIN_FILENO, &userInput, 1);
								write(1, &userInput, 1);

								if((int)userInput == 8 || (int)userInput == 127)
								{
									message.erase(message.size() - 1);
								}
								else if((int)userInput == 27)
								{
									cout << " ~exiting chat~" << endl;
									out = 1;
									break;
								}
								else if(userInput != '\n')
								{
									message.append(string(1,userInput));
								}
							}while(userInput != '\n');
							message.append("\0");
							if(out == 0)
							{
								bzero(mydataBuf, BUFFER_SIZE);
							    *(mydataBuf + 0) = 'P';
							    *(mydataBuf + 1) = '2';
							    *(mydataBuf + 2) = 'P';
							    *(mydataBuf + 3) = 'I';
							    if(clientList[j]->encrypted == 0)
							    {
									*(mydataBuf + 5) = 9;
							    	strcpy((mydataBuf+6),(char*)message.c_str());
							    	sendsize = 6 + (strlen((char*)message.c_str())) + 1;
							    }
							    else
							    {
							    	*(mydataBuf + 5) = 0x0D;
							    	*(uint16_t*)myanchorBuf = 0xA5A5;
							    	strcpy((myanchorBuf+2),(char*)message.c_str());
							    	PrivateEncryptDecrypt((uint8_t*)myanchorBuf, (strlen((char*)message.c_str()))+2 , clientList[j]->sequenceNum);
							    	sendsize = 6 + (strlen((char*)message.c_str())) + 2;
							    	strcpy((mydataBuf+6),myanchorBuf);
							    }
								write(clientList[j]->fd, &mydataBuf, sendsize);
							}
						}while(out == 0);
					}

					else if(userInput == 'u')
					{
						bzero(mydataBuf, BUFFER_SIZE);
					    *(mydataBuf + 0) = 'P';
					    *(mydataBuf + 1) = '2';
					    *(mydataBuf + 2) = 'P';
					    *(mydataBuf + 3) = 'I';
						*(mydataBuf + 5) = 7;
				    	sendsize = 6;
						write(clientList[j]->fd, &mydataBuf, sendsize);
					}
									
					
				}
				else if(userInput == 'd')
				{
					cout << "Who would you like to disconnect from? (q to cancel)" << endl;
					for(j = 0; j < clientList.size(); j++)
					{
						if(clientList[j]->connected == 1)
							cout << j << ")  UDP port: " << clientList[j]->udp_port
							<< "  TCP port: " << clientList[j]->tcp_port
							<<  " " << clientList[j]->user_name << "@" 
							<< clientList[j]->host_name << endl;
						read (STDIN_FILENO, &userInput, 1);
						cancel = 0;
						if(userInput != 'q')
						{
							while(!(userInput-'0' >= 0 && userInput-'0' < clientList.size()))
							{
								cout << endl << "invalid choice" << endl;
								read (STDIN_FILENO, &userInput, 1);
								write (1, &userInput, 1);
								if(userInput == 'q')
								{
									cout << "Cancelled" << endl;
									cancel = 1;
									break;
								}
							}
							if (cancel == 0)
							{
								bzero(mydataBuf, BUFFER_SIZE);
							    *(mydataBuf + 0) = 'P';
							    *(mydataBuf + 1) = '2';
							    *(mydataBuf + 2) = 'P';
							    *(mydataBuf + 3) = 'I';
							    value = 0x0A;
								lo = value & 0xFF;
								hi = value >> 8;
								*(mydataBuf + 4) = hi;
								*(mydataBuf + 5) = lo;
								write(clientList[j]->fd, &mydataBuf, 6);
								clientList[j]->connected = 0;
								allpoll.erase(allpoll.begin()+(clientList[j]->fdid));
								close(clientList[j]->fd);
							}
						}
					}
				}
				else if(userInput == 'e')
				{
					if(encrypt == 1)
					{
						cout << "Encryption disabled" << endl;
						encrypt = 0;
					}
					if(encrypt == 0)
					{
						if(passConf == 1)
						{
							cout << "Encryption enabled" << endl;
							encrypt = 1;
						}
						else
							cout << "Incorrect user/password. Cannot encrypt." << endl;
					}
				}
				else if(userInput == 'p')
				{
					cout << endl << "Request Encrypted connection from: (0,1,2,3...) " << endl;
					for(j = 0; j < clientList.size(); j++)
					{
						//if(clientList[j]->encrypted == 0)
							cout << j << ")  UDP port: " << clientList[j]->udp_port
							<< "  TCP port: " << clientList[j]->tcp_port
							<<  " " << clientList[j]->user_name << "@" 
							<< clientList[j]->host_name << endl;
					}
					read (STDIN_FILENO, &userInput, 1);

					if(encrypt == 1)
					{
						bzero(mydataBuf, BUFFER_SIZE);
					    *(mydataBuf + 0) = 'P';
					    *(mydataBuf + 1) = '2';
					    *(mydataBuf + 2) = 'P';
					    *(mydataBuf + 3) = 'I';
						*(mydataBuf + 5) = 0x0B;
						string message = user + '\0';
					    strcpy((mydataBuf+6),(char*)message.c_str());

					    sendsize = 7 + (strlen((char*)message.c_str()));

					    data = htonll(ekey);
					    *(uint64_t*)(mydataBuf + sendsize) = data;
					    sendsize += 8;

					    data = htonll(nkey);
					    *(uint64_t*)(mydataBuf + sendsize) = data;
					    sendsize += 8;
					    //clientList[k]->encrypted = 1;
					    Server = gethostbyname(clientList[(userInput-'0')]->host_name);
					    bcopy((char *)Server->h_addr, (char *)&to.sin_addr.s_addr, Server->h_length);
					    to.sin_port = htons(clientList[(userInput-'0')]->tcp_port);

					    clientList[(userInput-'0')]->fd = tcpfd;
						clientList[(userInput-'0')]->fdid = allpoll.size();
						mysock.fd = tcpfd;
						allpoll.push_back(mysock);

				        if(0 > connect(tcpfd, (struct sockaddr *)&to, sizeof(to)))
				        {
	    					error("ERROR connecting");
	    				}
						write(tcpfd, mydataBuf, sendsize);
					}
					else
					{
						cout << "encryption disabled. Cannot establish encrypted communication." << endl;
					}
				}
			}
			else
			{
				for(m = 3; m < allpoll.size(); m++)
				{
					if(allpoll[m].revents & POLLIN)
					{
						for(n = 0; n < clientList.size(); n++)
						{
							if(clientList[n]->fdid == m)
								break;
						}
						break;
					}
				}

				bzero(recbuffer, BUFFER_SIZE);
				read(clientList[n]->fd,recbuffer,BUFFER_SIZE-1);

				if(strncmp(recbuffer, "P2PI", 4) == 0)
				{
					value = recbuffer[5] | uint16_t(recbuffer[4]) << 8;
					if(value == 0x0A)
					{
						cout << "Closing Connection from client: " << clientList[n]->user_name <<
						"@" << clientList[n]->host_name << endl;
						clientList[n]->connected = 0;
						allpoll.erase(allpoll.begin()+clientList[n]->fdid);
						close(clientList[n]->fd);
					}
					else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 5)
					{
						clientList[n]->connected = 1;
						cout << "Connection accepted" << endl;
					}
					else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 6)
					{
						cout << "User Unavailable" << endl;
						clientList[n]->connected = 0;
						allpoll.erase(allpoll.begin()+clientList[n]->fdid);
						close(clientList[n]->fd);
		
					}
					else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 7)
					{
						cout << "Sending User List to " << clientList[n]->user_name <<
						"@" << clientList[n]->host_name << endl;
						bzero(mydataBuf, BUFFER_SIZE);
						message = "";
					    *(mydataBuf + 0) = 'P';
					    *(mydataBuf + 1) = '2';
					    *(mydataBuf + 2) = 'P';
					    *(mydataBuf + 3) = 'I';
						*(mydataBuf + 5) = 8;
						*(mydataBuf + 6) = (clientList.size() >> 24) & 0x00FF;
						*(mydataBuf + 7) = (clientList.size() >> 16) & 0x00FF;
						*(mydataBuf + 8) = (clientList.size() >> 8) & 0x00FF;
						*(mydataBuf + 9) = (clientList.size() >> 0) & 0x00FF;
				    	sendsize = 10;

						for(j = 0; j < clientList.size(); j++)
						{
							*(mydataBuf + sendsize) = (j >> 24) & 0x00FF;
							sendsize++;
							*(mydataBuf + sendsize) = (j >> 16) & 0x00FF;
							sendsize++;
							*(mydataBuf + sendsize) = (j >> 8) & 0x00FF;
							sendsize++;
							*(mydataBuf + sendsize) = (j >> 0) & 0x00FF;
							sendsize++;
							*(mydataBuf + sendsize) = (clientList[j]->udp_port >> 8) & 0x00FF;
							sendsize++;
							*(mydataBuf + sendsize) = (clientList[j]->udp_port >> 0) & 0x00FF;
							sendsize++;

							message = "";
							message = clientList[j]->host_name + '\0';
							cout << message << endl;
						    strcpy((mydataBuf+sendsize),(char*)message.c_str());
						    sendsize += (strlen((char*)msg.c_str())) + 1;

							*(mydataBuf + sendsize) = (clientList[j]->tcp_port >> 8) & 0x00FF;
							sendsize++;
							*(mydataBuf + sendsize) = (clientList[j]->tcp_port >> 0) & 0x00FF;
							sendsize++;	

							message = "";
							message = clientList[j]->user_name + '\0';
						    strcpy((mydataBuf+sendsize),(char*)message.c_str());
						    sendsize += (strlen((char*)msg.c_str())) + 1;
						    
					
						}
						write(clientList[n]->fd, &mydataBuf, sendsize);

					}
					else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 8)
					{
						clientList[n]->entryCount = ntohl(*(uint32_t*)(recbuffer + 6));
						clientList[n]->entryCounter = 0;
						cout << "User List from " << clientList[n]->user_name << "@" 
						<< clientList[n]->host_name << ":" << endl;
						
					}
					else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 9)
					{
						cout << clientList[n]->user_name << "@" 
						<< clientList[n]->host_name << ">> " << flush;
						write(1, recbuffer+6, strlen(recbuffer+6));
						write(1,"\n",1);
					}
					else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 0x00C)
					{
						cout << "Established Encrypted Communication with " << clientList[n]->user_name << "@" 
						<< clientList[n]->host_name << endl;

						//clientList[n]->connected = 1;

						datahigh = ntohll(*(uint64_t*)(recbuffer + 7));
						PublicEncryptDecrypt(datahigh, dkey, nkey);

						datalow = ntohll(*(uint64_t*)(recbuffer + 15));
						PublicEncryptDecrypt(datalow, dkey, nkey);
						
						clientList[n]->sequenceNum = datahigh << 32 | datalow;			
						cout << clientList[n]->sequenceNum << endl;
					}
					else if((ntohs(*(uint16_t*)(recbuffer + 4))) == 0x000D)
					{
						cout << "got encrypted message" << endl;

						/*PrivateEncryptDecrypt((uint8_t*)recbuffer+6, (strlen(recbuffer)-6) , clientList[n]->sequenceNum);
						cout << *(uint16_t*)recbuffer+6 << endl;*/
					}
				}
				else   //not P2PI
				{
					//entryCount = clientList[n]->entryCounter;
					/*bzero(mydataBuf, BUFFER_SIZE);
					strncpy(mydataBuf, recbuffer+3, 1);
					*(mydataBuf + 1) = ')';
					*(mydataBuf + 2) = ' ';
					strncpy(mydataBuf+3, "UDP: ", 5);
					strncpy(mydataBuf+8, recbuffer+4, 1);
					strncpy(mydataBuf+9, recbuffer+5, 1);

					j = 6;
					while((recbuffer+j) != '\n')
					{
						strncpy((mydataBuf+(j+4)), )
						j++;
					}*/
						cout << "User " << flush;
						cout << recbuffer+4 << endl;
						/*
					clientList[n]->iov[entryCount].iov_base = recbuffer+6;
					clientList[n]->iov[entryCount].iov_len = strlen(recbuffer+4);
					(clientList[n]->entryCounter)++;

					if(clientList[n]->entryCounter == clientList[n]->entryCount)
					{
						cout << "User List from " << clientList[n]->user_name << "@" 
						<< clientList[n]->host_name << ":" << endl;
						write(1, clientList[n]->iov, clientList[n]->entryCount);
						clientList[n]->entryCounter = 0;
					}*/
				}
			}
	    }
	    timeout_broadcast(&timeout, &time_out, &timefirst, maxtime, selfdiscover);

	}


    close(sockfd);
    restore_can(); 

    return 0;
}



