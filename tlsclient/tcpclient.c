#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netdb.h>

#define BUFF_SIZE 9000
#define RETRY_TIME 3

struct sockaddr_in peerAddr;

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);

   return tunfd;
}

void tunSelected(int tunfd, int fd){
   
    int  len;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
  
    printf("from tunfd:%s, len:%d\n",buff,len);
    write(fd, buff, len);
}

void socketSelected (int tunfd, int fd){
    int  len;
    char buff[BUFF_SIZE];

    bzero(buff, BUFF_SIZE);
    len = read(fd, buff, BUFF_SIZE);
    printf("from tunnel:%s\n",buff); 
    write(tunfd, buff, len);
}

int setupTCPClient(const char* ip, int port)
{
   struct sockaddr_in server_addr;
   server_addr.sin_family = AF_INET; 
   server_addr.sin_addr.s_addr = inet_addr(ip); 
   server_addr.sin_port  = htons(port);

   // Create a TCP socket
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Connect to the destination
   connect(sockfd, (struct sockaddr *) &server_addr,
           sizeof(server_addr));

   return sockfd;
}


int main(int argc, char *argv[])
{
   /*----------------Create a TCP connection ---------------*/
   int tunfd, sockfd;
   sockfd = setupTCPClient("128.230.215.187", 55555);
   tunfd  = createTunDevice();

   /*----------------Send/Receive data --------------------*/
   char buf[9000];
   char sendBuf[200];
   
   fd_set readFDSet;
   while(1){
     
     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd); 
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd);
     
     usleep(10000);  
  } 
}
