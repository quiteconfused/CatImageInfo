#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pcap.h>
#include <zlib.h>
#include <curl/curl.h> //your directory may be different



#define USE_THREADING

#ifdef USE_THREADING
#include <pthread.h>
#endif

#ifndef MAX_PATH
#define MAX_PATH 0x400
#endif

#define TOKENS " _-!#\?=\"\'/\\;,.:()<>+*&^%$@~`{}|][:1234567890"
#define _GNU_SOURCE

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

#define PRINT_PACKET
#define PROCESS_PACKET

#define DELIM "<>"

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */

#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)

#define HTTP_HEADER "HTTP/1.1 200 OK"
#define GET_HEADER "GET "
#define VISUALLY_SIMILAR "Visually similar"

pcap_t *handle;				/* packet capture handle */
unsigned char* servername = NULL;
unsigned char* portstring = NULL;

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        unsigned int /*tcp_seq*/ th_seq;                 /* sequence number */
        unsigned int /*tcp_seq*/ th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
        u_char  th_flags;
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct packets {
	unsigned int size;
	void* buf;
	unsigned int seq;
	unsigned int ack;
	TAILQ_ENTRY(packets) entries;
};


struct tcp_session {
	TAILQ_HEAD(, packets) dhead;
	TAILQ_HEAD(, packets) shead;
	struct in_addr src_ip;
	struct in_addr dst_ip;
	unsigned short sport;
	unsigned short dport;
	unsigned int start_seq;
	unsigned int start_ack;
	time_t last_timestamp;
	TAILQ_ENTRY(tcp_session) entries;          /* List. */
};


struct entry {
   char* string;
   unsigned int item_size;
   TAILQ_ENTRY(entry) entries;         /* Tail queue. */
};

void print_buffer(const unsigned char* buffer, unsigned int size);

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

void get_info(char* filename, void *head){
	CURL* curl; //our curl object

	curl = curl_easy_init();
	setup_request(curl, filename, head);
	curl_easy_perform(curl);

	curl_easy_cleanup(curl);
}

#ifdef USE_THREADING
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

void* entry_point(void* arg){
	char* filename = (unsigned char*) arg;
	TAILQ_HEAD(, entry) head;
	struct entry *np;
	unsigned int recieved_size = 0;
	unsigned int current_loc = 0; 
	char* complete_html = 0, *buf=0, *complete_html_copy=0, *visually_similar_offset=0, *previous_buffer_offset=0;   
	unsigned int scanlinks=0;
#ifdef USE_THREADING
	pthread_mutex_lock(&mutex);
#endif
	TAILQ_INIT(&head);                      /* Initialize the queue. */
	get_info(filename, &head);	
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
	if(1){
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
					if(servername!=NULL && portstring!=NULL){
    					send_results_to_server(servername, portstring, completed_string);
    				}
					notcomplete=0;
					free(completed_string);
				}
				else {
					printf("[MISSED] %s\n", filename);
					notcomplete=0;
				}
			}
			previous_buffer_offset = buf;
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
#ifdef USE_THREADING
	free(arg);
	fflush(stdout);
	pthread_mutex_unlock(&mutex);
	pthread_exit(0);
#endif
	return NULL;
}

/*
 * app name/banner
 */
void print_app_banner(void)
{

}

/*
 * print help text
 */
void print_app_usage(char** argv)
{

	printf("Usage: %s [interface] [-s server port]\n\nOptions:\n\tinterface\tListen on <interface> for packets.\n\n", argv[0]);
	return;
}

void print_buffer(const unsigned char* buffer, unsigned int size){
	
	unsigned int new_size = size%16==0?size:size + (16 - (size % 16));
	unsigned char new_buffer[new_size];
	unsigned x=0;

	memset(new_buffer, 0, new_size);

	memcpy(new_buffer, buffer, size);

	for(x=0; x<new_size; x+=16)
		printf("    %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x - %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
		new_buffer[x], new_buffer[x+1], new_buffer[x+2], new_buffer[x+3], new_buffer[x+4], new_buffer[x+5], new_buffer[x+6], new_buffer[x+7],
		new_buffer[x+8], new_buffer[x+9], new_buffer[x+10], new_buffer[x+11], new_buffer[x+12], new_buffer[x+13], new_buffer[x+14], new_buffer[x+15],
		(isprint(new_buffer[x]) && x < size )?new_buffer[x]:'.',
		(isprint(new_buffer[x+1]) && x+1 < size )?new_buffer[x+1]:'.', 
		(isprint(new_buffer[x+2]) && x+2 < size )?new_buffer[x+2]:'.', 
		(isprint(new_buffer[x+3]) && x+3 < size )?new_buffer[x+3]:'.', 
		(isprint(new_buffer[x+4]) && x+4 < size )?new_buffer[x+4]:'.',  
		(isprint(new_buffer[x+5]) && x+5 < size )?new_buffer[x+5]:'.', 
		(isprint(new_buffer[x+6]) && x+6 < size )?new_buffer[x+6]:'.', 
		(isprint(new_buffer[x+7]) && x+7 < size )?new_buffer[x+7]:'.', 
		(isprint(new_buffer[x+8]) && x+8 < size )?new_buffer[x+8]:'.', 
		(isprint(new_buffer[x+9]) && x+9 < size )?new_buffer[x+9]:'.', 
		(isprint(new_buffer[x+10]) && x+10 < size )?new_buffer[x+10]:'.', 
		(isprint(new_buffer[x+11]) && x+11 < size )?new_buffer[x+11]:'.', 
		(isprint(new_buffer[x+12]) && x+12 < size )?new_buffer[x+12]:'.', 
		(isprint(new_buffer[x+13]) && x+13 < size )?new_buffer[x+13]:'.', 
		(isprint(new_buffer[x+14]) && x+14 < size )?new_buffer[x+14]:'.', 
		(isprint(new_buffer[x+15]) && x+15 < size )?new_buffer[x+15]:'.');
}

unsigned int prepare_image(char* filename, char* out_buffer, unsigned int uncompressed_size){
					
	FILE *temp_file = NULL;
	unsigned int wrote = 0;
	char cwd[1600]={0};
	char new_file[MAX_PATH]={0};
	char new_cmd[MAX_PATH]={0};
	char *tmp=NULL;
#ifdef USE_THREADING
	pthread_t tinfo;
	pthread_attr_t attr;
#endif
	
	getcwd(cwd, 1600);
	
	filename = strtok_r(filename, "!#\?=\"\'", &tmp);

	sprintf(new_file, "%s/images/%s", cwd, filename);

	temp_file = fopen(new_file, "w+");

	if(temp_file==NULL)
		return 0;

	do{
		wrote += fwrite(out_buffer+wrote, 1, uncompressed_size-wrote, temp_file);
	} while(wrote < uncompressed_size);


	fclose(temp_file);
#ifndef USE_THREADING	
	if(!fork()){
		entry_point(new_file);
		_exit(0);
	}
#else
	unsigned char* copy = malloc(strlen(new_file)+1);
	memset(copy, 0, strlen(new_file)+1);
	strcpy(copy, new_file);
	pthread_create(&tinfo, NULL, &entry_point, copy);
	
#endif
	return 1;
}

unsigned int process_packet(struct tcp_session* stream){

	struct packets *packets = NULL;
	char* incoming_buffer=NULL;
	char* outgoing_buffer=NULL;
	char* incoming_buffer_copy=NULL;
	char* outgoing_buffer_copy=NULL;
	char* temp_buffer = NULL;
	char filename[MAX_PATH]={0};	
	unsigned int outgoing_size = 0;
	unsigned int incoming_size = 0;
	unsigned int temp = 0;
	unsigned int outgoing_temp = 0;
	unsigned int incoming_temp = 0;
	unsigned int return_val = 0;
	const char path_termination[]="/";
	const char string_termination[] = "\r\n\r\n";
	const char line_termination[] = "\r\n";
	const char content_type_string[] = "Content-Type: ";
	const char transfer_encoding_string[] = "Transfer-Encoding: ";
	const char content_encoding_string[] = "Content-Encoding: ";
	const char content_length_string[] = "Content-Length: ";
	const char gzip_string[] = "gzip";
	const char chunked_string[] = "chunked";
	const char text_html_string[] = "text/html";
	const char text_css_string[] = "text/css";
	const char text_string[] = "text";
	const char image_jpeg_string[] = "image/jpeg";
	const char image_png_string[] = "image/png";
	const char image_gif_string[] = "image/gif";

	for(packets = stream->dhead.tqh_first; packets !=NULL; packets = packets->entries.tqe_next){
		incoming_size+=packets->size;	
	}
	incoming_buffer = malloc(incoming_size+1);
	memset(incoming_buffer, 0, incoming_size+1);
	while(stream->dhead.tqh_first != NULL){
		struct packets *lowest = stream->dhead.tqh_first;
		for(packets = stream->dhead.tqh_first; packets !=NULL; packets = packets->entries.tqe_next){
			if(ntohl(lowest->seq)-ntohl(stream->start_seq)>ntohl(packets->seq)-ntohl(stream->start_seq)){
				lowest = packets;
			}
		}
		memcpy(incoming_buffer + temp, lowest->buf, lowest->size);
		temp+=lowest->size;

		free(lowest->buf);
		TAILQ_REMOVE(&stream->dhead, lowest, entries);
		free(lowest);

	}

	temp=0;	
	for(packets = stream->shead.tqh_first; packets !=NULL; packets = packets->entries.tqe_next){
		outgoing_size+=packets->size;	
	}
	outgoing_buffer = malloc(outgoing_size+1);
	memset(outgoing_buffer, 0, outgoing_size+1);
	while(stream->shead.tqh_first != NULL){
		struct packets *lowest = stream->shead.tqh_first;
		for(packets = stream->shead.tqh_first; packets !=NULL; packets = packets->entries.tqe_next){
			if(ntohl(lowest->ack)-ntohl(stream->start_ack)>ntohl(packets->ack)-ntohl(stream->start_ack)){
				lowest = packets;
			}
		}
		memcpy(outgoing_buffer + temp, lowest->buf, lowest->size);
		temp+=lowest->size;
		free(lowest->buf);

		TAILQ_REMOVE(&stream->shead, lowest, entries);
		free(lowest);
	}
		
	outgoing_buffer_copy = malloc(outgoing_size+1);
	incoming_buffer_copy = malloc(incoming_size+1);
	
	memset(outgoing_buffer_copy, 0, outgoing_size+1);
	memset(incoming_buffer_copy, 0, incoming_size+1);
	
	memcpy(outgoing_buffer_copy, outgoing_buffer, outgoing_size);
	memcpy(incoming_buffer_copy, incoming_buffer, incoming_size);
	
	outgoing_temp = 0;
	incoming_temp = 0;

	do{
		if(!strncmp(outgoing_buffer_copy+outgoing_temp, GET_HEADER, sizeof(GET_HEADER)-1)){
			unsigned int pathname_size = strchr(outgoing_buffer_copy+outgoing_temp+sizeof(GET_HEADER)-1, ' ') - (outgoing_buffer_copy+outgoing_temp+sizeof(GET_HEADER)-1) + 1;
			char* temp_buffer2 = malloc(pathname_size);
			char* pathname = NULL;
			char* tmp2=NULL;
			
			memset(temp_buffer2, 0, pathname_size);
			memcpy(temp_buffer2, outgoing_buffer_copy+outgoing_temp+sizeof(GET_HEADER)-1, pathname_size-1);
			
			for(pathname = strtok_r(temp_buffer2,path_termination, &tmp2); pathname!=NULL; pathname = strtok_r(NULL, path_termination, &tmp2)){
				if(strcasestr(pathname, ".jpeg") || strcasestr(pathname, ".jpg") || strcasestr(pathname, ".png") || strcasestr(pathname, ".gif")){
					strcpy(filename, pathname);
					
					if(!strncmp(incoming_buffer_copy+incoming_temp, HTTP_HEADER, sizeof(HTTP_HEADER)-1) && strstr(incoming_buffer_copy+incoming_temp, string_termination)!=NULL){
						unsigned int header_size = strstr(incoming_buffer_copy+incoming_temp, string_termination) - (incoming_buffer_copy + incoming_temp)+strlen(string_termination);
						unsigned int content_length = 0;
						unsigned char* header = malloc(header_size+1);
						unsigned char* temp_header_str = NULL;
						char *tmp3=NULL;
						
						memset(header, 0, header_size+1);
						memcpy(header, incoming_buffer_copy+incoming_temp, header_size);

						for(temp_header_str = strtok_r(header, line_termination, &tmp3); temp_header_str!=NULL; temp_header_str = strtok_r(NULL, line_termination, &tmp3)){
					
							if(!strncmp(temp_header_str, content_length_string, strlen(content_length_string))){
								content_length=atoi(temp_header_str+strlen(content_length_string));
							}			
						}
						
						if(content_length){
							prepare_image(filename, incoming_buffer_copy+incoming_temp+header_size, content_length);
							return_val =1;			
						}							
									
						if(strstr(incoming_buffer_copy+incoming_temp+header_size, HTTP_HEADER)==NULL){
							incoming_temp = incoming_size;
						} else {
							incoming_temp += strstr(incoming_buffer_copy+incoming_temp+header_size, HTTP_HEADER) - (incoming_buffer_copy + incoming_temp);
						}

						free(header);
					}
				}					
			}
			
			free(temp_buffer2);
		}
		
		if(strstr(outgoing_buffer_copy+outgoing_temp, line_termination)==NULL)
			outgoing_temp = outgoing_size;
		else
			outgoing_temp += strstr(outgoing_buffer_copy+outgoing_temp, line_termination) - (outgoing_buffer_copy+outgoing_temp) + sizeof(line_termination)-1;
			
	} while(outgoing_temp<outgoing_size && incoming_temp<incoming_size);
	
	
	free(incoming_buffer_copy);
	free(incoming_buffer);
	free(outgoing_buffer_copy);
	free(outgoing_buffer);

	return return_val;
}

void finish_packet(struct tcp_session *stream, const struct sniff_tcp *tcp, const struct sniff_ip *ip){
	struct packets *packets = NULL;
	unsigned int return_val = process_packet(stream);
}


/*
 * dissect/print packet
 */
void
got_packet(u_char *arg, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *packet_payload;             /* Packet payload */
	int size_ip;
	int size_tcp;
	int packet_size_payload;
	unsigned char* buf = NULL;
	struct tcp_session *stream=NULL;
	TAILQ_HEAD(listhead, tcp_session) *head = (void*)arg;
	unsigned int match_found=0;
	unsigned int terminate = 0;

	count++;
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		return;
	}
	
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			//printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			//printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			//printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			//printf("   Protocol: IP\n");
			return;
		default:
			//printf("   Protocol: unknown\n");
			return;
	}

	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		return;
	}
	
	/* define/compute tcp payload (segment) offset */
	packet_payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	packet_size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	if(tcp->th_flags & (TH_FIN | TH_ACK)==(TH_FIN | TH_ACK))
		terminate = 1;
	
	if(tcp->th_flags & TH_SYN){
	
		struct tcp_session *temp_stream = malloc(sizeof(struct tcp_session));
		memset(temp_stream, 0, sizeof(struct tcp_session));

		TAILQ_INIT(&temp_stream->shead);
		TAILQ_INIT(&temp_stream->dhead);
		*(unsigned int*)&temp_stream->dst_ip= *(unsigned int*)&ip->ip_dst;
		*(unsigned int*)&temp_stream->src_ip= *(unsigned int*)&ip->ip_src;
		temp_stream->sport = tcp->th_sport;
		temp_stream->dport = tcp->th_dport;
		temp_stream->start_seq = tcp->th_seq;
		temp_stream->start_ack = tcp->th_ack;
		temp_stream->last_timestamp = time(NULL);
		TAILQ_INSERT_TAIL(head, temp_stream, entries);
		stream = temp_stream;
	} else {
		struct tcp_session *temp_stream=NULL;
		for (temp_stream = head->tqh_first; temp_stream != NULL && stream==NULL; temp_stream = temp_stream->entries.tqe_next){
			if( *(unsigned int*)&temp_stream->dst_ip==*(unsigned int*)&ip->ip_dst && 
				temp_stream->dport == tcp->th_dport && 
				*(unsigned int*)&temp_stream->src_ip==*(unsigned int*)&ip->ip_src && 
				temp_stream->sport == tcp->th_sport){
				stream=temp_stream;
			} else if( 	*(unsigned int*)&temp_stream->dst_ip==*(unsigned int*)&ip->ip_src && 
					temp_stream->dport == tcp->th_sport && 
					*(unsigned int*)&temp_stream->src_ip==*(unsigned int*)&ip->ip_dst && 
					temp_stream->sport == tcp->th_dport){
				stream=temp_stream;
				match_found=1;
			} else {
			}
		}
	}
	
	if(stream==NULL){

	} else {
		time_t current_time = time(NULL);
		struct packets *temp_packets=match_found?stream->dhead.tqh_first:stream->shead.tqh_first;
		struct packets *packets=NULL;
		
		while(temp_packets!=NULL){
			if(	temp_packets->seq == tcp->th_seq && 
				temp_packets->ack == tcp->th_ack)
				packets = temp_packets;
			temp_packets = temp_packets->entries.tqe_next;
		}

		if(packets!=NULL){
			free(packets->buf);
			packets->size = packet_size_payload;
			packets->buf = malloc(packet_size_payload);
			memcpy(packets->buf, packet_payload, packet_size_payload);
		} else {
			struct packets *newpacket = malloc(sizeof(struct packets));

			newpacket->buf = malloc(packet_size_payload);
			memcpy(newpacket->buf, packet_payload, packet_size_payload);
			newpacket->size = packet_size_payload;
			newpacket->seq = tcp->th_seq;
			newpacket->ack = tcp->th_ack;

			if(match_found){
				TAILQ_INSERT_TAIL(&stream->dhead, newpacket, entries);
			} else {
				TAILQ_INSERT_TAIL(&stream->shead, newpacket, entries);
			}
		}

		stream->last_timestamp = current_time;

		if(terminate){
			finish_packet(stream, tcp, ip);
			TAILQ_REMOVE(head, stream, entries);
			free(stream);
		}
	} 
	
	//if(!terminate){
	//	struct tcp_session *temp_stream=NULL;
	//	for (temp_stream = head->tqh_first; temp_stream != NULL; temp_stream = temp_stream->entries.tqe_next){
	//		time_t current_time = time(NULL);
	//		if(current_time-temp_stream->last_timestamp > 3){
	//			//finish_packet(temp_stream, tcp, ip);
	//			//TAILQ_REMOVE(head, temp_stream, entries);
	//		} 
	//	}
	//}

	return;
}

void exit_program(int sig) {
	if(sig == SIGINT)
		pcap_breakloop(handle);
	if(sig == SIGCHLD){
		unsigned int status;
		wait(&status);
	}
}


int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */

	char filter_exp[] = "";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = -1;			/* number of packets to capture */


	TAILQ_HEAD(listhead, tcp_session) head;
	struct listhead *headp;                 /* List head. */

	TAILQ_INIT(&head);                       /* Initialize the list. */

	curl_global_init(CURL_GLOBAL_ALL); //pretty obvious

	print_app_banner();

	signal(SIGINT, exit_program);
	signal(SIGCHLD, exit_program);
	
	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc==5  && !memcmp(argv[2], "-s", 2)){
        servername = argv[3];
        portstring = argv[4];
        dev = argv[1]	;
	} else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		print_app_usage(argv);
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	
	int datalink_type = 0;

	/* make sure we're capturing on an Ethernet device [2] */
	if ((datalink_type = pcap_datalink(handle)) != DLT_EN10MB) {
		fprintf(stderr, "Datalink type is %d, %s not Ethernet\n", datalink_type, dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}


	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, (unsigned char *)&head);


	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	curl_global_cleanup();

	return 0;
}

