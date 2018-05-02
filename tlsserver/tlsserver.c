#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }

#define PORT_NUMBER 55555
#define BUFF_SIZE 9000

struct sockaddr_in peerAddr;

int  setupTCPServer();                   // Defined in Listing 19.10
void processRequest(SSL* ssl, int sock); // Defined in Listing 19.12

int Authen_client(SSL* ssl, int sockfd, fd_set readFDSet)
{
    char username[256], passwd[256];
    int  len, time;
    int read_packet=0;
    bzero(username, 256);
    bzero(passwd, 256);


      printf ("Authentication: SSL connection\n");
  
      while(1){
      FD_ZERO(&readFDSet);
      FD_SET(sockfd, &readFDSet);
      select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
      if (FD_ISSET(sockfd, &readFDSet)) {
           read_packet++;
           printf("Authen: received a packet No.%d\n",read_packet);
           if (read_packet == 1){
              SSL_read(ssl, username, sizeof(username)-1);}
           else{
              SSL_read(ssl, passwd, sizeof(passwd)-1);
	      break;}
       }
       usleep(1000000);
     }
   return login(username,passwd);
}

int main(){

  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  int err;

  // Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  // Step 1: SSL context initialization
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
  // Step 2: Set up the server certificate and private key
  SSL_CTX_use_certificate_file(ctx, "./cert_xie/server-cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "./cert_xie/server-key.pem", SSL_FILETYPE_PEM);
  // Step 3: Create a new SSL structure for a connection
  ssl = SSL_new (ctx);

  // Step 4: Create a tunnel interface
  int tunfd  = createTunDevice();
  
  struct sockaddr_in sa_client;
  size_t client_len;
  int listen_sock = setupTCPServer();


  
  while(1){
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
   
    int pipefd[2]; 
    int cpid = fork();
    if (cpid == -1) {
          perror("fork");
          exit(EXIT_FAILURE);
    }

    if (cpid == 0) { // The child process
        
       close (listen_sock);

       SSL_set_fd (ssl, sock);
       err = SSL_accept (ssl);
       CHK_SSL(err);
       printf ("SSL connection established!\n");
       fd_set readFDSet;
       if (Authen_client(ssl, sock, readFDSet)== -1) {printf("client authenticated failed!"); exit(1);}
 
       while(1){ //child process keep alive 
       FD_ZERO(&readFDSet);
       FD_SET(sock, &readFDSet);
       //FD_SET(pipefd[0],&readFDSet);
       FD_SET(tunfd, &readFDSet);
       select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
  
        if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
        //if (FD_ISSET(pipefd[0],  &readFDSet)) pipeSelected(pipefd[0], ssl);
        if (FD_ISSET(sock, &readFDSet)) socketSelected(tunfd,ssl);
    //   close(sock);
    //   return 0;
       usleep(100000);}
    } else { // The parent process
       close(sock);
       //fd_set readFDSet;
       //FD_SET(tunfd, &readFDSet);
       //if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl, pipefd[1]);
   }
    usleep(100000);
  }
}


int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (4433);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);

   return tunfd;
}

//child write to ssl
void pipeSelected(int fd, SSL* ssl){
    int  len;
    unsigned char buff[BUFF_SIZE];
    char dst_ip[20];

    printf("Got a packet from parent pipe\n");

    bzero(buff, BUFF_SIZE); 
    len = read(fd, buff, BUFF_SIZE);
   
  // Destination addr
    sprintf(dst_ip,"%d.%d.%d.%d",(unsigned char)(buff[16]),
                        (unsigned char)(buff[17]),
                        (unsigned char)(buff[18]),
                        (unsigned char)(buff[19]));
     printf("dst:%s\n",dst_ip);
     SSL_write(ssl, buff, len);
}

//parent send to child
void tunSelected(int tunfd, SSL* ssl, int fd){
    int  len;
    unsigned char buff[BUFF_SIZE];
    char dst_ip[20];

    printf("Got a packet from tunfd\n");
  
    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);

     printf("From:%d.%d.%d.%d\n",(unsigned char)(buff[12]),
                        (unsigned char)(buff[13]),
                        (unsigned char)(buff[14]),
                        (unsigned char)(buff[15]));
 
   
  // Destination addr
    sprintf(dst_ip,"%d.%d.%d.%d",(unsigned char)(buff[16]),
                        (unsigned char)(buff[17]),
                        (unsigned char)(buff[18]),
                        (unsigned char)(buff[19])); 
       printf("To:%s\n",dst_ip);
       //SSL_write(ssl, buff, len);
//       write(fd, buff, BUFF_SIZE);
     SSL_write(ssl, buff, len);
}

void socketSelected (int tunfd, SSL* ssl) {
    int  len;
    unsigned char buff[BUFF_SIZE];
    unsigned char dst_ip[20];

    printf("Got a packet from the ssl socket\n");

    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, BUFF_SIZE);

    sprintf(dst_ip,"%d.%d.%d.%d",(unsigned char)(buff[12]),
                        (unsigned char)(buff[13]),
                        (unsigned char)(buff[14]),
                        (unsigned char)(buff[15]));
    printf("From:%s\n",dst_ip);
    // Destination addr
    printf("To:%d.%d.%d.%d\n", (unsigned char)(buff[16]),
                        (unsigned char)(buff[17]),
                        (unsigned char)(buff[18]),
                        (unsigned char)(buff[19])); 
   // buff[len] = '\0';
   // printf("from ssl:%s, len:%d\n",buff,len); 
    write(tunfd, buff, len);
}





