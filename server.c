#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8765
#define BUFFSIZE 256
/* use these strings to tell the marker what is happening */
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"
#define FMT_NO_VERIFY "ECE568-SERVER: Certificate does not verify\n"

//strings
#define CLIENT_EMAIL "ece568alice@ecf.utoronto.ca"
#define HOST "Alice's Client"

SSL_CTX* CreateCTX(void){

    SSL_library_init();
    SSL_load_error_strings();
    SSL_METHOD *method = SSLv23_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
   
    //check errors and return the context

    if(NULL==ctx){
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    
    if (SSL_CTX_set_cipher_list(ctx, "ALL") <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }
    //load private key
    if(SSL_CTX_use_PrivateKey_file(ctx, "bob.pem", SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        exit(-3);
    }
    //load cert
    if(SSL_CTX_use_certificate_chain_file(ctx, "bob.pem") <=0){
        ERR_print_errors_fp(stderr);
        exit(-4);
    }
    
    SSL_CTX_set_default_passwd_cb_userdata(ctx, "password");
    
    if(!SSL_CTX_check_private_key(ctx)){
	fprintf(stderr, "private key and public certificate dont match\n");
	exit(-5);
    }
    
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if(!(SSL_CTX_load_verify_locations(ctx, "568ca.pem", 0)))
    {
	fprintf(stderr, "Cannot read CA List\n");
	exit(-6);
    }    
    
    return ctx;
}

//get the cert and compare the common name to the hostname
//if they don't match exit
void check_cert(SSL* ssl){
    if(SSL_get_verify_result(ssl)!=X509_V_OK){
        printf(FMT_NO_VERIFY);
        exit(0);
    }
    X509 *peer = SSL_get_peer_certificate(ssl);
    char peer_CN[BUFFSIZE];
    char peer_EM[BUFFSIZE];
    if(NULL!=peer){
        X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, BUFFSIZE);       
        
        if(strcasecmp(peer_CN,HOST)){
            fprintf(stderr,"\n");
            exit(0);
        }

        X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_EM, BUFFSIZE);

        if(strcasecmp(peer_EM, CLIENT_EMAIL)){
            fprintf(stderr,"\n");
            exit(0);
        }
        //print out email and client
        printf(FMT_CLIENT_INFO, peer_CN, peer_EM);
        X509_free(peer);
    }else{
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stderr);
        exit(-8);
    }

}

int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  struct sockaddr_in sin;
  int val=1;
  pid_t pid;
  SSL_CTX *ctx;
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  ctx = CreateCTX();

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);
  
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    /*fork a child to handle the connection*/
    
    if((pid=fork())){
      close(s);
    }
    else {
      /*Child code*/
      int len;
      char buf[256];
      char *answer = "42";
   
      BIO* sbio = BIO_new_socket(s,BIO_NOCLOSE);
      SSL* ssl;
      ssl = SSL_new(ctx);
      SSL_set_bio(ssl,sbio,sbio);

      if(SSL_accept(ssl)<=0){
          printf(FMT_ACCEPT_ERR);
          ERR_print_errors_fp(stdout);
          exit(0);
      }else{
          check_cert(ssl);
      }

      //debug
      printf("connection successful using Version: %s, Cipher %s\n", SSL_get_version(ssl), SSL_get_cipher(ssl));

      len = SSL_read(ssl, &buf, 255);
      if(len<=0){
          printf("SSL read error\n");
      }
      //print spec 4.2
      buf[len]= '\0';
      printf(FMT_OUTPUT, buf, answer);

      int err = SSL_write(ssl, answer, strlen(answer));
      if(err<=0){
          err = SSL_get_error(ssl, err);
          printf("Error writing failed with: %d\n",err);
      }      


      //shutdown
      int r = SSL_shutdown(ssl);
      if(!r){
          shutdown(s,1);
          r = SSL_shutdown(ssl);
      }


      switch(r){
          case 1:
              break;
          case 0:
          case -1:
          default:
              printf(FMT_INCOMPLETE_CLOSE);
      }
      SSL_free(ssl);
      close(sock);
      close(s);
      return 0;
    }
  }
  
  close(sock);
  return 1;
}
