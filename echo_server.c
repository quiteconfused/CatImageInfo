#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

void print_usage(char** argv){
	printf("Usage: %s <port>\n", argv[0]);
}

unsigned int parse_client(int sock, struct sockaddr_in *cli_addr, unsigned int message_key){
	int n;
	char buffer[1600];
	time_t times = time(NULL);
	char date[30]={0};
	char *date_copy=NULL;
	  
	bzero(buffer,1600);
	n = read(sock,buffer,1600);
	if (n < 0){
		printf("Error reading from socket");
		return 0;
	}
	
	strncpy(date, ctime(&times), 30);
	date_copy = strtok(date, "\n");
	
	printf("[0x%08x], [%s], [%s], [%s]\n", message_key, date_copy, inet_ntoa(cli_addr->sin_addr), buffer); fflush(stdout);
	
	fflush(stdout);
	
	memset(buffer, 0, 1600);
	
	sprintf(buffer, "Message Key: %d accepted\n", message_key);
	
	n = write(sock,buffer,strlen(buffer));
	if (n < 0){ 
		printf("Error writing to socket");
	}
	
	return 0;
}

int main(int argc, char** argv){
     int sockfd, newsockfd, portno;
     socklen_t clilen;
     char buffer[256];
     struct sockaddr_in serv_addr, cli_addr;
     int n;
     pid_t pid;
     unsigned int message_key=0;

	signal(SIGCHLD, SIG_IGN);

	if(argc<1){
		print_usage(argv);
		exit(1);
	}
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	
	if (sockfd < 0) {
		printf("Error opening socket\n");
		exit(1);
	}
	
     bzero((char *) &serv_addr, sizeof(serv_addr));
     portno = atoi(argv[1]);
//	 portno = 5158;
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_addr.s_addr = INADDR_ANY;
     serv_addr.sin_port = htons(portno);
     if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
     	printf("Error binding socket on port %d\n", portno);
     	exit(1);
     }
     
     listen(sockfd,5);
     
     clilen = sizeof(struct sockaddr_in);
     while (1) {
         newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
         message_key++;
         if (newsockfd < 0){
             printf("Error on accept\n");
             exit(1);
         }
         pid = fork();
         if (pid < 0){
             printf("Error on fork\n");
             exit(1);
         }
         if (pid == 0)  {
             close(sockfd);
             parse_client(newsockfd, &cli_addr, message_key);
             exit(0);
         }
         else{ 
         	close(newsockfd);
         }
     } /* end of while */
     close(sockfd);
     return 0; /* we never get here */
}
