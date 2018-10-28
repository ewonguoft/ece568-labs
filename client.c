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

#define HOST "localhost"
#define PORT 8765
#define BUFFSIZE 256

/* use these strings to tell the marker what is happening */
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"

#define SERVER_CN "Bob's Server"
#define SERVER_EMAIL "ece568bob@ecf.utoronto.ca"


SSL_CTX* CreateCTX(void){

    SSL_library_init();
    SSL_load_error_strings();
    SSL_METHOD *method = SSLv23_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
   
    //check errors and return the context

    if(ctx==NULL){
        ERR_print_errors_fp(stderr);
        exit(-1);
    }
    
    if (SSL_CTX_set_cipher_list(ctx, "ALL") <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(-2);
    }
    //load private key
    if(SSL_CTX_use_PrivateKey_file(ctx, "alice.pem", SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        exit(-3);
    }
    //load cert
    if(SSL_CTX_use_certificate_chain_file(ctx, "alice.pem") <=0){
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

void check_cert(SSL* ssl){
    if(SSL_get_verify_result(ssl)!=X509_V_OK){
        printf(FMT_NO_VERIFY);
        exit(0);
    }
    X509 *peer = SSL_get_peer_certificate(ssl);
    char peer_CN[BUFFSIZE];
    char peer_EM[BUFFSIZE];
    char peer_cert[BUFFSIZE];
    if(peer!=NULL){
        X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, BUFFSIZE);       
        
        if(strcasecmp(peer_CN, SERVER_CN)){
            printf(FMT_CN_MISMATCH);
            ERR_print_errors_fp(stderr);
            exit(-7);
        }

        X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_pkcs9_emailAddress, peer_EM, BUFFSIZE);

        if(strcasecmp(peer_EM, SERVER_EMAIL)){
            printf(FMT_EMAIL_MISMATCH);
            ERR_print_errors_fp(stderr);
            exit(-8);
        }

	char *issuer = X509_NAME_oneline(X509_get_issuer_name(peer),0,0);
	//int nid_cert_issuer = X509_get_issuer_name( "ece568" );
	//X509_NAME_get_text_by_NID(X509_get_subject_name(peer), nid_cert_issuer, peer_cert, BUFFSIZE);

        //print out server CN, email, and certificate issuer
        printf(FMT_SERVER_INFO, peer_CN, peer_EM, issuer);

        X509_free(peer);
    }else{
        printf(FMT_CONNECT_ERR);
        ERR_print_errors_fp(stderr);
        exit(-9);
    }

}


int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  SSL_CTX *ctx;
  
  /*Parse command line arguments*/
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  /*get ip address of the host*/
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  ctx = CreateCTX();

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  
  /*open socket*/
  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");

  BIO* sbio = BIO_new_socket(sock,BIO_NOCLOSE);
  SSL* ssl;
  ssl = SSL_new(ctx);
  SSL_set_bio(ssl,sbio,sbio);

  if(SSL_connect(ssl)<=0){
    printf(FMT_CONNECT_ERR);
    ERR_print_errors_fp(stdout);
    exit(0);
  }else{
    check_cert(ssl);
  }
  
  //send(sock, secret, strlen(secret),0);
  int err = SSL_write(ssl, secret, strlen(secret));
  if(err<=0){
    err = SSL_get_error(ssl, err);
    printf("Error writing failed with: %d\n",err);
  }  

  //len = recv(sock, &buf, 255, 0);
  len = SSL_read(ssl, &buf, 255);
  if(len<=0){
    printf("SSL read error\n");
  }

  buf[len]='\0';
  
  /* this is how you output something for the marker to pick up */
  printf(FMT_OUTPUT, secret, buf);

  //shutdown
      int r = SSL_shutdown(ssl);
      if(!r){
          shutdown(sock,1);
          r = SSL_shutdown(ssl);
      }


      switch(r){
          case 1:
              break;
          case 0:
          case -1:
          default:
              printf(FMT_INCORRECT_CLOSE);
      }
      SSL_free(ssl);
  
  close(sock);
  return 1;
}
