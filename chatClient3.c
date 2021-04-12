/*
   File: chatClient2.c
   Course: CENG320
   Author: Alexander Guglenko
   Date: Sunday Sep 28, 2020   2:33 PM

*/



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdbool.h> 
#include <readline/readline.h> 
#include <arpa/inet.h>
#include <pthread.h>

#define PORT "40056" // my port 

#define MAXDATASIZE 100 // max number of bytes we can get at once 

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int connectSocket(char *address)
{
   int rv,sockfd;
   struct addrinfo hints, *servinfo, *p;
   char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(address, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit (1);
    }

    // loop through all the results and connect to the first we can
    // create.  Usually that's the first one.
    for(p = servinfo; p != NULL; p = p->ai_next) {
	if ((sockfd = socket(p->ai_family, p->ai_socktype,
			p->ai_protocol)) == -1) {
	    perror("client: socket");
	    continue;
	}

	if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
	    close(sockfd);
	    perror("client: connect");
	    continue;
	}

	break;
    }

    if (p == NULL) {
	fprintf(stderr, "client: failed to connect\n");
	exit(1);
    } 

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
	    s, sizeof s);
    printf("client: connecting to %s\n", s);

   return sockfd;
}

void *receiveThread(void *arg)
{
   int numbytes;   
   char incoming[1000];  

   while(1)
   {
      bzero(incoming, sizeof incoming);
      //Receive message from server 
  	   if ((numbytes = recv((int) arg, incoming, sizeof incoming -1 , 0)) == -1) 
      {  
         perror("recv");
	   	pthread_exit(0);
      }
      if(strcasecmp(incoming,"logout")==0) break;

      fprintf(stdout,"%s\n",incoming);
      }	
   pthread_exit(0); 
}


int main(int argc, char *argv[])
{  
   char buf[MAXDATASIZE];
   int sockfd;
   pthread_t thread;

    if (argc != 2) {
        fprintf(stderr,"usage: client hostname\n");
        exit(1);
    }
   
   //save returned fd from call to function
   //which connects to socket
   sockfd = connectSocket(argv[1]);

      if(pthread_create(&thread,NULL,receiveThread,(void *) sockfd))
         perror("Failure to create a thread");

    int numbytes; 
    while(true) //Synchronized conversation loop                                       
    { 
       char *msg=readline(""); 
       if ( msg) {
          if( numbytes=send(sockfd, msg,strlen(msg)+1, 0) == -1) {
               perror("send: Server probably quit"); 
               break;
               }
            } 

           if(strcasecmp(msg,"logout")==0)
                break;

          } //end of conversation loop      
      pthread_join(thread,NULL);
      close(sockfd); 
  } 
