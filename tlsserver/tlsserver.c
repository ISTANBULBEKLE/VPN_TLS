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


      //fd_set readFDSet;
      //SSL_set_fd (ssl, sockfd);
      //int err = SSL_accept (ssl);    
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
    
    if (fork() == 0) { // The child process
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
       FD_SET(tunfd, &readFDSet);
       select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
  
       if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, ssl);
       if (FD_ISSET(sock, &readFDSet)) socketSelected(tunfd,ssl);
    //   close(sock);
    //   return 0;
       usleep(100000);}
    } else { // The parent process
        close(sock);
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

/*void processRequest(SSL* ssl, int sock)
{
    char buf[1024];
    int len = SSL_read (ssl, buf, sizeof(buf) - 1);
    buf[len] = '\0';
    printf("Received: %s\n",buf);

    // Construct and send the HTML page
    char *html =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/html\r\n\r\n"
	"<!DOCTYPE html><html>"
	"<head><title>Hello World</title></head>"
	"<style>body {background-color: black}"
	"h1 {font-size:3cm; text-align: center; color: white;"
	"text-shadow: 0 0 3mm yellow}</style></head>"
	"<body><h1>Hello, world!</h1></body></html>";
    SSL_write(ssl, html, strlen(html));
//    SSL_shutdown(ssl);  SSL_free(ssl);
}*/

int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);

   return tunfd;
}

void tunSelected(int tunfd, SSL* ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from tunfd\n");
  
    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    //printf("from tunfd:%s, len:%d\n",buff,len);
    
    SSL_write(ssl, buff, len);
    //SSL_shutdown(ssl);  SSL_free(ssl);
}

void socketSelected (int tunfd, SSL* ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the ssl\n");

    bzero(buff, BUFF_SIZE);
    len = SSL_read(ssl, buff, BUFF_SIZE);
   // buff[len] = '\0';
   // printf("from ssl:%s, len:%d\n",buff,len); 
    write(tunfd, buff, len);
}




