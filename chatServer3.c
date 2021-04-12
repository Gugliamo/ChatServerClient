/*
   File: chatServer2.c
   Course: CENG320
   Author: Alexander Guglenko
   Date: Sunday Sep 28, 2020   2:33 PM

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h> 
#include <readline/readline.h>
#include <readline/history.h>
#include <pthread.h>
#include <semaphore.h>

#define PORT "40056"  // my port

#define BACKLOG 10     // how many pending connections queue will hold
#define PORTHOLDER 99999 //a large number that fd hopefully will never reach
sem_t mutex;


void sendMSG(int fd, char *msg);

void sigchld_handler(int s)
{
    while(waitpid(-1, NULL, WNOHANG) > 0);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// get port, IPv4 or IPv6:
uint16_t get_in_port(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return (((struct sockaddr_in*)sa)->sin_port);
    }

    return (((struct sockaddr_in6*)sa)->sin6_port);
}

void stdNewline(char *input)
{
  int n=strlen(input); 
  if(n>1) 
  {
    if(input[n-2]=='\r' & input[n-1]=='\n')  //Detect telnet/windows cr  newline null
     {                                      //replace with  newline null
       input[n-2]='\0'; 
      } 
    else if(input[n-1]=='\n') input[n-1]='\0'; 
    } 
 } 
int bindSocket(char *port);


struct USERLIST
{
   char *ip;
   int port;   
   char *name;
   int fd; 
   long threadID;
   int status;  
}
userList[20];

//help command function
char *helpCMD(char *cmd, char **tokens)
{
   return("\nAvailable commands:\n"
         "help(current)\n"
         "login\n"
         "logout\n"
         "list\n"
         "private\n");
}

//login command function
char *loginCMD(char *cmd, char **tokens)
{
   sem_wait(&mutex);
   int i,tokenCount;

   //count how many tokens were passed
   for(i=0;tokens[i];i++)
      tokenCount = i;

   //checking that user put in the right amount
   //of parameters for this command
   if(tokenCount != 0)
      {
         sem_post(&mutex);
         return ("Invalid parameters for login command.\n"
                "Use: login username or login \"multi-word username\"\n");
      }
   //find current user using threadID in userList
   //then set new name in list using tokens[0]
   for(i=0;userList[i].threadID;i++)
      if(userList[i].threadID == pthread_self())
         strcpy(userList[i].name,tokens[0]);

   sem_post(&mutex);
   return "Name changed.\n";
}

//logout command function
char *logoutCMD(char *cmd, char **tokens)
{
   sem_wait(&mutex);
   int i,index;
   int fd;    

   //search through userList struct,
   //find index which contains current threadID,
   //and grab fd from the same index
   for(i=0;userList[i].threadID;i++)
      if(userList[i].threadID == pthread_self())
      {
         fd = userList[i].fd;
         index=i;
      }

   //clearing index
   userList[index].name = "free";
   userList[index].ip = "free";
   userList[index].port = 0;
   userList[index].fd = PORTHOLDER;
  // userList[index].threadID = 404;//can't reset this if i want to reclaim thread
   userList[index].status = 2;//ready to be reclaimed   

   sem_post(&mutex);
   return "logout";
}

//list command function
char *listCMD(char *cmd, char **tokens)
{
   sem_wait(&mutex);
   int i;
   static char result[1000];
   char temp[100];
   bzero(result,sizeof result);
   bzero(temp,sizeof temp);

   strcpy(result,"Users online:\n");
   for(i=0;userList[i].name;i++)
   {
      if(userList[i].name != NULL &&
         strcmp(userList[i].name,"free") != 0)
      {
         sprintf(temp,"%s\n",userList[i].name);
         strcat(result,temp);
      }       
   }
   sem_post(&mutex);
   return result;
}

//private command function
char *privateCMD(char *cmd, char **tokens)
{
   sem_wait(&mutex);
   int i, tokenCounter, fd;
   char message[1000], temp[25];
   bzero(message, sizeof message);
   bzero(temp, sizeof temp);

   //check for proper amount of parameters from user
   //input and display message if incorrect
   for(i=0;tokens[i];i++)
      tokenCounter = i;
   if(tokenCounter < 1)
      {
         sem_post(&mutex);
         return ("Invalid parameters for private command.\n"
                  "Use: private username message\n");
      }

   //finding fd of user the message will be sent to
   for(i=0;userList[i].name;i++)
      if(strcasecmp(userList[i].name, tokens[0]) == 0)
         fd = userList[i].fd;

   //building message string
   for(i=1;tokens[i];i++)
   {
      bzero(temp,sizeof temp);
      sprintf(temp,"%s ",tokens[i]);
      strcat(message,temp);
   }
   //sending message
   sem_post(&mutex);
   sendMSG(fd,message);   
   return "sending private message\n";
}

//struct holding command and corresponding function names
struct CMDSTRUCT
{
   char *cmd;
   char *(*method)();
   char *help;
}
cmdStruct[]={{"help",helpCMD},
               {"login",loginCMD},
               {"logout",logoutCMD},
               {"list",listCMD},
               {"private",privateCMD},
               {NULL,NULL}};




char *interpret(char *cmdline)
{
   sem_wait(&mutex);
   char **tokens;
   char *cmd;
   int i;


   tokens=history_tokenize(cmdline);
   if(!tokens) return "";//if user pressed return with nothing in it, return nothing
   cmd=tokens[0];//sace first tokenized string of command in cmd variable

   //if user input matches command, execute it
   for(i=0;cmdStruct[i].cmd;i++)
      if(strcasecmp(cmd,cmdStruct[i].cmd)==0)
         {
            sem_post(&mutex);
            return (cmdStruct[i].method)(cmd,&tokens[1]);
         }
   sem_post(&mutex);
   
   //if user input does not match a command, return sendAll
   //to signify message must be sent to everyone
   return "sendAll";
}

//function to send a message to a single fd
void sendMSG(int fd, char *msg)
{
   sem_wait(&mutex);
   int numbytes;

   if(numbytes=send(fd,msg,strlen(msg)+1,0) == -1)
      perror("Error with sending message");
   sem_post(&mutex);
}

//function to send messages to everyone 
//except the sender
void sendMSGAll(int fd, char *msg)
{
   sem_wait(&mutex);
   int numbytes, i;
   char userSentList[500],temp[50];
   bzero(userSentList,sizeof userSentList);
   bzero(temp,sizeof temp);
   
   sprintf(userSentList,"\nMessage sent to:\n");

   //loop sending everyone the message
   for(i=0;userList[i].fd;i++)
   { 
      //don't send to indexs which have been "cleared"
      //or to original sender 
      if(userList[i].fd == PORTHOLDER ||
         userList[i].fd == fd)
         continue;
      //otherwise send it to everyone 
      else if(numbytes=send(userList[i].fd, msg, strlen(msg)+1,0) == -1)
         perror("Error sending message to all");
      
      //grab names of users sent message and build list     
      sprintf(temp,"%s\n",userList[i].name);
      strcat(userSentList,temp);
      }
   
      sem_post(&mutex);
      //this is a workaround for an issue below
      sendMSG(fd,userSentList);
      
      //originally tried to send the userSentList with the lines below
      //but client keeps receiving it incomplete/broken
  // if(numbytes=send(fd, userSentList, strlen(msg)+1,0) == -1)
  //    perror("Error sending original user a SentList");       
}
  


//function to check and join unused threads
void threadCheck()
{
   sem_wait(&mutex);
   int status, i;
   fprintf(stdout,"Thread checker initialized.\n");

   //loop through userList struct
   for(i=0;userList[i].fd;i++)
   {
      //if status flag is set to 2 and
      //pthread_kill returns something other than 0
      //then join the thread
      if(userList[i].status == 2 && 
         pthread_kill((pthread_t) userList[i].threadID,0) != 0) 
      {       
         fprintf(stdout,"Joining thread %lu\n",userList[i].threadID);
         pthread_join((pthread_t)userList[i].threadID,NULL);
         userList[i].status = 0;//set status flag to 0, thread unused
         fprintf(stdout,"Status flag changed to %d\n",userList[i].status);
      }         
   }
   sem_post(&mutex);
  
}


//function for writing a server log
void writeFile(char *msg)
{
   sem_wait(&mutex);
   FILE *fp;
   //char buffer[1000];
 
   fp=fopen("part3Log.txt","a");
   if(fp==NULL)
      perror("Error opening file");
   else
      fprintf(fp,"%s\n",msg);

   fclose(fp);  
   sem_post(&mutex);
}

//main function initial thread creation is sent to
void *serverThread(void *fd)
{
   int i,current, numbytes;
   char incoming[10000];
   char *response;



   //adding pthreadID to appropriate userList entry
   //by searching for the same fd that was passed to this thread
   for(i=0;userList[i].fd;i++)
      if(userList[i].fd == (int) fd)
      {
         userList[i].threadID = pthread_self();
         userList[i].status = 1; //thread is active
      }

   
   while(1)
   {
      //Receive message from client
      if ((numbytes = recv((int) fd, incoming, sizeof incoming -1 , 0)) == -1) 
      {
	      perror("recv");
		   break;
      }
      //make sure to process message if it comes from telnet
      stdNewline(incoming);
      //print out the message to the server console
      fprintf(stdout,"%s\n",incoming);	
      writeFile(incoming);
      //interpret whatever message is coming in
      response = interpret(incoming);
   
      //if interpret returns "sendAll", send msg to
      //all users except for the person who sent it
      if(strcmp(response,"sendAll") == 0)
      {
         sendMSGAll((int) fd, incoming);
         writeFile(response);
         sem_post(&mutex);
         continue;
      }
      //print out response to server console
      fprintf(stdout,"%s\n",response);
      //send message and fd to function which
      //handles output to client
      sendMSG((int) fd, response);
      writeFile(response);
      
      if(strcmp(response,"logout") == 0)
         break;

   }
   close((int)fd);
   pthread_exit(0);
}


int main(void)
{
    int i, sockfd, new_fd[20];  //listening on sockfd, new connection on new_fd
    struct sockaddr_storage their_addr; // connector's address information
   int port;//hold port number
    socklen_t sin_size;
    int yes=1;
    char s[INET6_ADDRSTRLEN];
   char userName[20][50];
   sem_init(&mutex,0,1);
   int counter = 0;
   pthread_t thread[20];


    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
      

    fprintf(stdout,"Hello, I'm pid %d listening on port %s using TCP.\n"
            ,getpid(),PORT);

   //saving returned fd from function call to connect/bind socket	
   sockfd = bindSocket("40056"); 
 
    fprintf(stdout,"Server setup complete\n");

    


    while(true) {  // main accept() loop

      
      threadCheck(); //check to see if any threads need joining

      //attempt at setting the counter to earliest available index
      //by checking if an userList index was "cleared" after 
      //user has left. When cleared, the name member is set to "free"
     /* 
      for(i=0;userList[i].name;i++)
      {
         if(strcmp(userList[i].name,"free") == 0)
            {
               counter = i;
            }
         else
            counter = i+1;
      } */   

        sin_size = sizeof their_addr;

        //Create a 2nd socket that will be used to talk to the client
        fprintf(stdout,"Server is waiting for a new client\n");	
        new_fd[counter] = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
        if (new_fd[counter] == -1) {
            perror("accept");
            continue;
        }

        //Convert the binary network address of the client
        //to a printable string
        inet_ntop(their_addr.ss_family,
            get_in_addr((struct sockaddr *)&their_addr),
            s, sizeof s);

         //convert the binary port of the client
         //to a printable string
         port = htons(get_in_port((struct sockaddr *)&their_addr)); 
 
      //adding ip/port/username/fd to list
      sprintf(userName[counter],"Client#%d",counter+1);

      userList[counter].ip = s;
      userList[counter].name = userName[counter];
      userList[counter].port = port;
      userList[counter].fd = new_fd[counter];

        printf("server1: got connection from %s\n",s);  
     fprintf(stdout,"IP: %s\nName: %s\nPort:%d\nFD:%d\n",
               userList[counter].ip,
               userList[counter].name,
               userList[counter].port,
               userList[counter].fd);
   
      pthread_create(&thread[counter],NULL,serverThread,(void *)new_fd[counter]);
   
      
       counter++;
     
    } //end of accept loop
    fprintf(stdout,"Ending program\n");	
    return 0;
}

int bindSocket(char *port)
{
   
   struct addrinfo hints, *servinfo, *p;
   int sockfd; //listen on sock_fd
   struct sigaction sa;

   
   int rv;
   
    //Clear the hints data structure and set its values
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; //Could come back either AF_INET or AF_INET6
    hints.ai_socktype = SOCK_STREAM; //This server will use TCP not UDP
    hints.ai_flags = AI_PASSIVE; // use my IP


    //The server may have several network cards, each with a different address
    //Get the 1st one with this particular port that matches the hints
    //What we get back is a linked list of type struct addrinfo
    if ((rv = getaddrinfo(NULL, port , &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit (1);
    }

    // loop through all the results and bind to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("server1: socket");
            continue;
        }

        //bind the raw socket to the network card address and port
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("server1: bind");
            continue;
        }

        break;
    }

    if (p == NULL)  {
        fprintf(stderr, "server1: failed to bind\n");
        exit (2);
    }

    freeaddrinfo(servinfo); // all done with this structure
                            // Avoid a memory leak, return the storage
                            // used up by the linked list

    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

    sa.sa_handler = sigchld_handler; // reap all dead processes
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

   return sockfd;
}
