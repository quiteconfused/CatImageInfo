#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <curl/curl.h> //your directory may be different
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define VISUALLY_SIMILAR "Visually similar"

struct entry {
   char* string;
   unsigned int item_size;
   TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};

size_t writeCallback(char* buf, size_t size, size_t nmemb, void *head)
{ //callback must have this declaration
    //buf is a pointer to the data that curl has for us
    //size*nmemb is the size of the buffer
    
    struct entry *n1;
    
    n1 = (struct entry*)malloc(sizeof(struct entry));
    n1->string = (char*)malloc(size*nmemb+1);
    n1->item_size=size*nmemb;
    memset(n1->string, 0, size*nmemb+1);
    memcpy(n1->string, buf, size*nmemb);
   	TAILQ_INSERT_TAIL((TAILQ_HEAD(, entry)*)head, n1, entries);
 	
    return size*nmemb; //tell curl how many bytes we handled
}

unsigned int send_results_to_server(char* hostname, char* port, char* results){
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[256];

    portno = atoi(port);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0){
        fprintf(stderr, "Error opening socket\n");
        return 1;
    }

    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        return 1;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(portno);

    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0) {
    	fprintf(stderr, "error connecting\n");
    	return 1;
    }

    n = write(sockfd,results,strlen(results));
    if (n < 0){
         fprintf(stderr, "Error writing to socket\n");
         return 1;
    }
    
    bzero(buffer,256);
    n = read(sockfd,buffer,255);
    if (n < 0) {
         fprintf(stderr, "Error reading from socket\n");
         return 1;
    }
    fprintf(stderr, "%s\n",buffer);
    close(sockfd);
    return 0;
}

void setup_request(CURL* curl, char *filename, void *head){
    struct curl_httppost* post=NULL;
    struct curl_httppost* last=NULL;

	curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, writeCallback);
	curl_easy_setopt (curl, CURLOPT_WRITEDATA, head);
	
	curl_easy_setopt(curl, CURLOPT_URL, "http://www.google.com/searchbyimage/upload");
	curl_easy_setopt (curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Windows NT 6.1; rv:8.0) Gecko/20100101 Firefox/8.0");
	curl_easy_setopt (curl, CURLOPT_HEADER, 0);
	curl_easy_setopt (curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt( curl, CURLOPT_CONNECTTIMEOUT, 20 );
	curl_easy_setopt (curl, CURLOPT_REFERER, "http://images.google.com/");

	curl_formadd(&post, &last, CURLFORM_COPYNAME, "image_url", CURLFORM_COPYCONTENTS, "" , CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "btnG", CURLFORM_COPYCONTENTS, "Search", CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "encoded_image", CURLFORM_FILE, filename , CURLFORM_CONTENTTYPE, "image/jpeg", CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "image_content", CURLFORM_COPYCONTENTS, "", CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "filename", CURLFORM_COPYCONTENTS, "",CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "hl", CURLFORM_COPYCONTENTS, "en", CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "safe", CURLFORM_COPYCONTENTS, "off", CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "bih", CURLFORM_COPYCONTENTS, "", CURLFORM_END);
	curl_formadd(&post, &last, CURLFORM_COPYNAME, "biw", CURLFORM_COPYCONTENTS, "", CURLFORM_END);	

	curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
}

#define DELIM "<>"

void get_info(char* filename, unsigned int option, void *head){
    CURL* curl; //our curl object

	curl_global_init(CURL_GLOBAL_ALL); //pretty obvious
	curl = curl_easy_init();
	setup_request(curl, filename, head);
	curl_easy_perform(curl);

	curl_easy_cleanup(curl);
	curl_global_cleanup();
}

void entry_point(char* filename, unsigned int option, unsigned char* servername, unsigned char* port){
	TAILQ_HEAD(, entry) head;
	struct entry *np;
	unsigned int recieved_size = 0;
	unsigned int current_loc = 0; 
	char* complete_html = 0, *buf=0, *complete_html_copy=0, *visually_similar_offset=0, *previous_buffer_offset=0;   
	unsigned int scanlinks=0;

	TAILQ_INIT(&head);                      /* Initialize the queue. */
	get_info(filename, option, &head);	
	for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next)
		recieved_size+=np->item_size;
		
	complete_html = (char*)malloc(recieved_size+1);
	complete_html_copy = (char*)malloc(recieved_size+1);
	memset(complete_html, 0, recieved_size+1);
	memset(complete_html_copy, 0, recieved_size+1);
	
	for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next){
		if(recieved_size && np->item_size){
			memcpy(complete_html+current_loc, np->string, np->item_size);
			memcpy(complete_html_copy+current_loc, np->string, np->item_size);
			current_loc+=np->item_size;
		}
	}
	if(option<2){
		char* tempptr=NULL;
		int notcomplete=1;
		previous_buffer_offset = complete_html;	
		for(buf = strtok_r(complete_html, DELIM, &tempptr); buf!=NULL && notcomplete; buf = strtok_r(NULL, DELIM, &tempptr)){
			if(!memcmp(buf, VISUALLY_SIMILAR, sizeof(VISUALLY_SIMILAR)-1)){
				visually_similar_offset = complete_html_copy + (buf - complete_html);
				while(memcmp(visually_similar_offset, "q=", 2) && visually_similar_offset-complete_html_copy>previous_buffer_offset-complete_html)
					visually_similar_offset--;
				if(previous_buffer_offset-complete_html!=visually_similar_offset-complete_html_copy){
					unsigned int completed_string_max_size = recieved_size-(visually_similar_offset-complete_html_copy+2);
					unsigned char *completed_string = malloc(completed_string_max_size+1);
					unsigned char *copy_completed_string=completed_string;
					memset(completed_string, 0, completed_string_max_size+1);
					visually_similar_offset+=2;
					while(	memcmp(visually_similar_offset, "&amp", 4) && 
						copy_completed_string - completed_string < completed_string_max_size && 
						visually_similar_offset-complete_html_copy < previous_buffer_offset-complete_html+recieved_size){
						if(visually_similar_offset[0]=='+'){
							sprintf(copy_completed_string, "%c", ' ');
							copy_completed_string++;
						} else if(!memcmp(visually_similar_offset, "&#39;", 5)){
							visually_similar_offset+=4;
							sprintf(copy_completed_string, "%c", '\'');
							copy_completed_string++;
						}
						else{
							sprintf(copy_completed_string, "%c", visually_similar_offset[0]);
							copy_completed_string++;
						}
						visually_similar_offset++;
					}
					printf("[MATCHED] %s: %s\n", filename, completed_string);
					if(servername!=NULL && port!=NULL){
    					send_results_to_server(servername, port, completed_string);
    				}
					notcomplete=0;
					free(completed_string);
				}
				else {
					printf("[MISSED] %s\n", filename);
					notcomplete=0;
					if(option)
						scanlinks=1;
				}
			}
			previous_buffer_offset = buf;
		}
	}
	
	if(option>=2 || scanlinks){ 
		buf = complete_html;
		while(buf<complete_html+recieved_size){
			if(!memcmp(buf, "href=\"", 6)){
				char *temp_buf = buf+6;
				char print_buf[80]={0};
				memcpy(print_buf, temp_buf, 79);
				if(!memcmp(temp_buf, "/imgres?imgurl=", 15)){
					char* temp_buf2=temp_buf+15;
					while(memcmp(temp_buf2, "&amp", 4)){
						putchar(temp_buf2[0]);
						temp_buf2++;
					}
					putchar('\n');
				}
				else if(!memcmp(temp_buf, "http", 4)){
					while(temp_buf[0]!='\"'){
						putchar(temp_buf[0]);
						temp_buf++;
					}
					putchar('\n');
				}
			}
			buf++;
		}
	}

	while (head.tqh_first != NULL){
		np = head.tqh_first;
		free(np->string);
		TAILQ_REMOVE(&head, head.tqh_first, entries);
		free(np);
	}
	
	free(complete_html);
	free(complete_html_copy);

}

void print_usage(char** argv){
	printf("Usage: %s <0/1/2> <path_to_image> \n", argv[0]);
	printf("\t\t0: only print matches\n");
	printf("\t\t1: print matches OR print links\n");
	printf("\t\t2: print matches AND print links\n");
}


int main(int argc, char** argv)
{
    if(argc<3){
    	print_usage(argv);
    	exit(1);
    }

	if(argc<5)
		entry_point(argv[2], atoi(argv[1]), NULL, NULL); 
	else
		entry_point(argv[2], atoi(argv[1]), argv[3], argv[4]); 
		
    
    return 0;
    
}
