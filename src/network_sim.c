#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

/**
 * Joseph McGill
 * Fall 2016
 * This program starts 2 threads to send and receive frames amongst simulated
 * network hosts. The host config files can be found in the /hosts/ directory
 * Each instance of the program simulates one host. It first builds a routing
 * table using the Distance Vector protocol then parses/sends each frame.
 *
 * The program needs to be compiled with gcc network_sim.c
 * and can be ran with the supplied script "./run" which starts
 * 12 xterm terminals or an individual host can be ran with
 * "./a.out ./hosts/A.txt input_data.bin"
 **/

/* Struct for the MAC data of a Frame */
typedef struct {
    unsigned char version;
    unsigned char ihl;
    unsigned char type_of_service;
    unsigned char length[2];
    unsigned char identification[2];
    unsigned char flags;
    unsigned char fragment_offset[2];
    unsigned char time_to_live;
    unsigned char protocol;
    unsigned char header_checksum[2];
    unsigned char source_addr[4];
    unsigned char dest_addr[4];
    unsigned char* options;
    unsigned char* data;
    int num_of_options;
    int header_length;
    int total_packet_length;
} MAC_Data;

/* Struct for a Frame of data */
typedef struct {
    unsigned char frame_control[2];
    unsigned char duration_id[2];
    unsigned char addr1[6];
    unsigned char addr2[6];
    unsigned char addr3[6];
    unsigned char addr4[6];
    unsigned char src_addr[6];
    unsigned char dest_addr[6];
    unsigned char sequence_control[2];
    unsigned char llc[3];
    unsigned char org_code[3];
    unsigned char type[2];
    unsigned char* frame_data;
    MAC_Data mac_data;
    unsigned char frame_check_sequence[4];
    int total_frame_length;
    int to_ds;
    int from_ds;
    bool read_addr4;
} Frame;

/* struct for an entry in the routing table */
typedef struct {
    int dest[4];
    int next[4];
    int distance;
    struct sockaddr_in next_hop;
} Routing_Node;

/* struct for a Neighbor */
typedef struct {
    int fakeIP[4];
    struct sockaddr_in addr;
} Neighbor;

/* Global Variables */
struct sockaddr_in myaddr;
struct sockaddr_in clientaddr;
Neighbor* neighbors;
Routing_Node routing_table[64];
int fakeIP[4];
int fakeWLAN[6];
int port;
int noNeighbors;
int noFrames;
int noNodes;
int table_size;
int sock;
int response;


/* Function prototypes */
void* sender(void* file);
void* receiver();
void* send_routing_table();
void config(char* file);
void print_frame(Frame* f);
void fill_frame_data(Frame* f);
bool parse_frame(Frame* f, FILE *file_ptr, unsigned char* buffer,
                 int bytes_read);

/* Main function */
int main(int argc, char** argv) {

    /* set the host configuration */
    config(argv[1]);
    printf("%s\tIP: %d.%d.%d.%d\n", argv[1],
            fakeIP[0], fakeIP[1], fakeIP[2], fakeIP[3]);

    /* create the send thread */
    pthread_t send_thread, receive_thread;
    if (pthread_create(&send_thread,  NULL, &sender, argv[2]) != 0) {
        printf("\nFatal error: send thread could not be created");
        exit(-1);
    }

    /* create the receive thread */
    if (pthread_create(&receive_thread, NULL, &receiver, NULL) != 0) {
        printf("\nFatal error: receive thread could not be created");
        exit(-1);
    }

    /* close the threads */
    pthread_join(send_thread, NULL);
    pthread_join(receive_thread, NULL);

    /* exit the program */
    return 0;
}

/* Function to send data */
void* sender(void* file) {
    sleep(10);

    /* open the input file for reading */
    FILE *file_ptr;
    file_ptr = fopen((char *) file, "rb");

    /* arbitrarily sized Frame array */
    Frame frames[64];
    int frame_count = 0;
    bool read = true;

    /* parse the frames until a malformed frame is found (or EOF) */
    while (parse_frame(&frames[frame_count], file_ptr, NULL, 0) != false) {

        /* incrememnt the number of frames read */
        frame_count++;

        /* advance the file 12 bytes (space separating frames) */
        fseek(file_ptr, 12, SEEK_CUR);
    }

    /* send the frame if the source address matches the host's fake wlan */
    for (int i = 0; i < frame_count; i++) {

        /* send frames */
        if (frames[i].mac_data.source_addr[0] == fakeIP[0] &&
            frames[i].mac_data.source_addr[1] == fakeIP[1] &&
            frames[i].mac_data.source_addr[2] == fakeIP[2] &&
            frames[i].mac_data.source_addr[3] == fakeIP[3]) {

            /* send the frame to the next hop based on the routing table */
            for (int j = 0; j < table_size; j++) {
                if (routing_table[j].dest[0] == frames[i].mac_data.dest_addr[0]
                && routing_table[j].dest[1] == frames[i].mac_data.dest_addr[1]
                && routing_table[j].dest[2] == frames[i].mac_data.dest_addr[2]
                && routing_table[j].dest[3] == frames[i].mac_data.dest_addr[3]){
                    int sent = sendto(sock, frames[i].frame_data,
                               frames[i].total_frame_length,
                               0,
                               (struct sockaddr *) &routing_table[j].next_hop,
                               sizeof(routing_table[j].next_hop));
                }
            }
        }
    }

    /* free the memory allocated */
    for (int i = 0; i < frame_count; i++) {
        free(frames[i].mac_data.options);
        free(frames[i].mac_data.data);
        free(frames[i].frame_data);
    }
}

/* Function to receive data */
void* receiver() {

    /* number of frames received */
    int frames_received = 0;

    pthread_t table_thread;
    if (pthread_create(&table_thread,  NULL, &send_routing_table, NULL) != 0) {
        printf("\nFatal error: test thread could not be created");
        exit(-1);
    }

    /* receive indefinitely */
    while (1) {

        /* sockaddr  of sender */
        struct sockaddr_in rec_addr;
        bzero(&rec_addr, sizeof(rec_addr));
        int size = sizeof(rec_addr);

        /* buffer to hold the message */
        unsigned char buffer[1024];
        bzero(&buffer, 1024);

        /* wait for a message */
        int bytes_read = recvfrom(sock, buffer, 1024, 0,
                         (struct sockaddr *)&rec_addr, &size);

        /* if a routing table is received, check for updates */
        if (buffer[0] == 0x72 && buffer[1] == 0x6F &&
            buffer[2] == 0x75 && buffer[3] == 0x74) {

            /* parse the received routing table */
            int recv_table_size = buffer[4];
            int buffer_index = 5;

            /* routing table received */
            Routing_Node* new_table = (Routing_Node*)malloc(sizeof(Routing_Node)
                                       *recv_table_size);

            /* read the table entries */
            for (int i = 0; i < recv_table_size; i++) {

                bzero(&new_table[i], sizeof(new_table[i]));

                buffer_index++; //skip the \n char

                /* set the destination address */
                new_table[i].dest[0] = buffer[buffer_index];
                buffer_index++;

                new_table[i].dest[1] = buffer[buffer_index];
                buffer_index++;

                new_table[i].dest[2] = buffer[buffer_index];
                buffer_index++;

                new_table[i].dest[3] = buffer[buffer_index];
                buffer_index++;

                /* find which neighbor sent the table */
                for (int j = 0; j < noNeighbors; j++) {
                    if (neighbors[j].addr.sin_port == rec_addr.sin_port) {

                        /* set the next hop address */
                        new_table[i].next[0] = neighbors[j].fakeIP[0];
                        new_table[i].next[1] = neighbors[j].fakeIP[1];
                        new_table[i].next[2] = neighbors[j].fakeIP[2];
                        new_table[i].next[3] = neighbors[j].fakeIP[3];

                        /* set the actual port for the next hop */
                        new_table[i].next_hop = neighbors[j].addr;
                    }
                }

                /* set the distance for the destination */
                new_table[i].distance = buffer[buffer_index];
                buffer_index++;
                new_table[i].distance++;

            }

            /* check the received routing table for new information */
            bool table_updated = false;
            bool new_entry;
            for (int i = 0; i < recv_table_size; i++) {

                new_entry = true;

                /* check table entry against existing entries */
                for (int j = 0; j < table_size; j++) {
                    if (new_table[i].dest[0] == routing_table[j].dest[0] &&
                        new_table[i].dest[1] == routing_table[j].dest[1] &&
                        new_table[i].dest[2] == routing_table[j].dest[2] &&
                        new_table[i].dest[3] == routing_table[j].dest[3]) {

                        new_entry = false;

                        /* see if the entry is a shorter distance */
                        if (new_table[i].distance < routing_table[j].distance) {
                            routing_table[j].distance = new_table[i].distance;
                            routing_table[j].next[0] = new_table[i].next[0];
                            routing_table[j].next[1] = new_table[i].next[1];
                            routing_table[j].next[2] = new_table[i].next[2];
                            routing_table[j].next[3] = new_table[i].next[3];

                            /* update the entry if the weight is smaller */
                            routing_table[j].next_hop = new_table[i].next_hop;
                            table_updated = true;
                        }
                    }
                }

                /* add the entry if the current table doesn't have it */
                if (new_entry) {
                    routing_table[table_size].dest[0] = new_table[i].dest[0];
                    routing_table[table_size].dest[1] = new_table[i].dest[1];
                    routing_table[table_size].dest[2] = new_table[i].dest[2];
                    routing_table[table_size].dest[3] = new_table[i].dest[3];

                    routing_table[table_size].next[0] = new_table[i].next[0];
                    routing_table[table_size].next[1] = new_table[i].next[1];
                    routing_table[table_size].next[2] = new_table[i].next[2];
                    routing_table[table_size].next[3] = new_table[i].next[3];

                    routing_table[table_size].next_hop = new_table[i].next_hop;
                    routing_table[table_size].distance = new_table[i].distance;

                    table_size++;
                    table_updated = true;
                }
            }

            /* send the routing table to neighbors if it has been updated */
            if (table_updated) {
                unsigned char table_buffer[1024];
                int table_buffer_size = 0;
                bzero(&table_buffer, 1024);

                /* fill the buffer with 'rout' */
                table_buffer[0] = 0x72;
                table_buffer[1] = 0x6F;
                table_buffer[2] = 0x75;
                table_buffer[3] = 0x74;
                table_buffer[4] = table_size;
                table_buffer_size = 5;

                /* add the table entries to the buffer */
                for (int i = 0; i < table_size; i++) {

                    /* add newline (0xA) as a delimiter */
                    table_buffer[table_buffer_size] = 0xA;
                    table_buffer_size++;

                    /* add destination (as int, int, int, int) */
                    table_buffer[table_buffer_size] = routing_table[i].dest[0];
                    table_buffer_size++;

                    table_buffer[table_buffer_size] = routing_table[i].dest[1];
                    table_buffer_size++;

                    table_buffer[table_buffer_size] = routing_table[i].dest[2];
                    table_buffer_size++;

                    table_buffer[table_buffer_size] = routing_table[i].dest[3];
                    table_buffer_size++;

                    /* add distance (as int) */
                    table_buffer[table_buffer_size] = routing_table[i].distance;
                    table_buffer_size++;
                }

                /* send to all neighbors */
                for (int i = 0; i < noNeighbors; i++) {
                    int sent = sendto(sock, table_buffer, table_buffer_size, 0,
                                     (struct sockaddr *) &neighbors[i].addr,
                                      sizeof(neighbors[i].addr));

                }
            }

        } else {

            /* parse the received frame */
            Frame f;
            bool parsed = parse_frame(&f, NULL, buffer, bytes_read);

            /* check if the message is yours */
            if (parsed) {

                /* increment the frames received */
                frames_received++;

                /* check if the frame belongs to this host */
                if (f.mac_data.dest_addr[0] == fakeIP[0] &&
                    f.mac_data.dest_addr[1] == fakeIP[1] &&
                    f.mac_data.dest_addr[2] == fakeIP[2] &&
                    f.mac_data.dest_addr[3] == fakeIP[3]) {

                    /* print the source and destination of the frame */
                    printf("%d frame(s) received\n", frames_received);
                    printf("Source: %d.%d.%d.%d\n",
                            f.mac_data.source_addr[0],
                            f.mac_data.source_addr[1],
                            f.mac_data.source_addr[2],
                            f.mac_data.source_addr[3]);

                    printf("Destination: %d.%d.%d.%d (Me!)\n\n",
                            f.mac_data.dest_addr[0],
                            f.mac_data.dest_addr[1],
                            f.mac_data.dest_addr[2],
                            f.mac_data.dest_addr[3]);

                    /* print frame */
                    print_frame(&f);

                } else {

                    /* send the frame to the next hop based on
                     * the routing table */
                    for (int j = 0; j < table_size; j++) {
                        if (routing_table[j].dest[0] == f.mac_data.dest_addr[0]
                        && routing_table[j].dest[1] == f.mac_data.dest_addr[1]
                        && routing_table[j].dest[2] == f.mac_data.dest_addr[2]
                        && routing_table[j].dest[3] == f.mac_data.dest_addr[3]){

                            /* send the frame */
                            int sent = sendto(sock, f.frame_data,
                                 f.total_frame_length,
                                 0,
                                 (struct sockaddr *) &routing_table[j].next_hop,
                                 sizeof(routing_table[j].next_hop));

                            /* print the source and destination of the frame */
                            printf("%d frame(s) received\n", frames_received);
                            printf("Source: %d.%d.%d.%d\n",
                                    f.mac_data.source_addr[0],
                                    f.mac_data.source_addr[1],
                                    f.mac_data.source_addr[2],
                                    f.mac_data.source_addr[3]);

                            printf("Destination: %d.%d.%d.%d\n\n",
                                    f.mac_data.dest_addr[0],
                                    f.mac_data.dest_addr[1],
                                    f.mac_data.dest_addr[2],
                                    f.mac_data.dest_addr[3]);

                            /* uncomment this for hosts to print when the send
                            printf("Sending to: %d.%d.%d.%d on port %d\n\n",
                                    routing_table[j].next[0],
                                    routing_table[j].next[1],
                                    routing_table[j].next[2],
                                    routing_table[j].next[3],
                                    routing_table[j].next_hop.sin_port);
                            */
                        }
                    }
                }
            } else printf("Parse failed");
        }
    }
}

/* function to send a routing table to a node's neighbors */
void* send_routing_table() {

    /* sleep to allow receiving threads to start */
    sleep(5);

    /* buffer to hold the routing table */
    unsigned char table_buffer[1024];
    int table_buffer_size = 0;
    bzero(&table_buffer, 1024);

    /* fill the buffer with 'rout' and the table size */
    table_buffer[0] = 0x72;
    table_buffer[1] = 0x6F;
    table_buffer[2] = 0x75;
    table_buffer[3] = 0x74;
    table_buffer[4] = table_size;
    table_buffer_size = 5;

    /* add the table entries to the buffer */
    for (int i = 0; i < table_size; i++) {

        /* add newline (0xA) as a delimiter */
        table_buffer[table_buffer_size] = 0xA;
        table_buffer_size++;

        /* add destination (as int, int, int, int) */
        table_buffer[table_buffer_size] = routing_table[i].dest[0];
        table_buffer_size++;

        table_buffer[table_buffer_size] = routing_table[i].dest[1];
        table_buffer_size++;

        table_buffer[table_buffer_size] = routing_table[i].dest[2];
        table_buffer_size++;

        table_buffer[table_buffer_size] = routing_table[i].dest[3];
        table_buffer_size++;

        /* add distance (as int) */
        table_buffer[table_buffer_size] = routing_table[i].distance;
        table_buffer_size++;
    }

    /* send to all neighbors */
    for (int i = 0; i < noNeighbors; i++) {
        int sent = sendto(sock, table_buffer, table_buffer_size, 0,
                   (struct sockaddr *) &neighbors[i].addr,
                   sizeof(neighbors[i].addr));
    }
}

/* Function to set the configuration from the host file */
void config(char* file) {

    /* open the input file for reading */
    FILE *file_ptr;
    file_ptr = fopen(file, "r");

    response = 0;
    char* errormsg = "Fatal error: config could not be loaded\n";

    /* exit the program if the config file can't be read */
    if (file_ptr == NULL) {
        printf("\n%s", errormsg);
        exit(-1);
    }

    /* read the 'fake' IP address of the host from the file */
    char* line = NULL;
    size_t len;
    ssize_t bytes_read;

    /* exit if nothing is read */
    if ((bytes_read = getline(&line, &len, file_ptr)) == -1) {
        printf("\n%s", errormsg);
        exit(-1);
    }


    char* token;
    token = strtok(line, ".");
    int j = 0;
    fakeIP[j] = atoi(token);
    j++;
    while (token != NULL && j < 4) {
        token = strtok(NULL, ".");
        fakeIP[j] = atoi(token);
        j++;
    }

    /* read the port number */
    if ((bytes_read = getline(&line, &len, file_ptr)) == -1) {
        printf("\n%s", errormsg);
        exit(-1);
    }

    port = atoi(line);

    /* set the host sock address */
    myaddr.sin_family = AF_INET;
    myaddr.sin_port = htons(port);
    inet_aton("127.0.0.1", &myaddr.sin_addr);

    /* create and bind the socket */
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sock, (struct sockaddr *)&myaddr, sizeof(myaddr));

    /* read the number of neighbors */
    if ((bytes_read = getline(&line, &len, file_ptr)) == -1) {
        printf("\n%s", errormsg);
        exit(-1);
    }

    noNeighbors = atoi(line);

    /* initialize the neighbors array */
    neighbors = (Neighbor*)malloc(sizeof(Neighbor)*noNeighbors);

    /* parse the neighbors */
    for (int i = 0; i < noNeighbors; i++) {

        /* read the neighbor line */
        if ((bytes_read = getline(&line, &len, file_ptr)) == -1) {
            printf("\n%s", errormsg);
            exit(-1);
        }

        /* fill out the neighbor's information */
        bzero((char *)&neighbors[i], sizeof(neighbors[i]));
        neighbors[i].addr.sin_family = AF_INET;
        char* fakeIP = strtok(line, " ");
        char* realIP = strtok(NULL, " ");
        char* port = strtok(NULL, " ");

        /* set the fake IP of the neighbor */
        neighbors[i].fakeIP[0] = atoi(strtok(fakeIP, "."));
        neighbors[i].fakeIP[1] = atoi(strtok(NULL, "."));
        neighbors[i].fakeIP[2] = atoi(strtok(NULL, "."));
        neighbors[i].fakeIP[3] = atoi(strtok(NULL, "."));

        /* set the ip and port of the neighbor */
        inet_aton(realIP, &neighbors[i].addr.sin_addr);
        neighbors[i].addr.sin_port = htons(atoi(port));
    }

    /* build the initial routing table from the neighbors */
    table_size = noNeighbors;
    for (int i = 0; i < table_size; i++) {
        bzero(&routing_table[i], sizeof(routing_table[i]));

        /* set the destination address */
        routing_table[i].dest[0] = neighbors[i].fakeIP[0];
        routing_table[i].dest[1] = neighbors[i].fakeIP[1];
        routing_table[i].dest[2] = neighbors[i].fakeIP[2];
        routing_table[i].dest[3] = neighbors[i].fakeIP[3];

        /* set the next hop address */
        routing_table[i].next[0] = neighbors[i].fakeIP[0];
        routing_table[i].next[1] = neighbors[i].fakeIP[1];
        routing_table[i].next[2] = neighbors[i].fakeIP[2];
        routing_table[i].next[3] = neighbors[i].fakeIP[3];

        /* set the actual port for the next hop */
        routing_table[i].next_hop = neighbors[i].addr;

        /* set the distance for the destination */
        routing_table[i].distance = 1;
    }

    /* add this node to the routing table */
    routing_table[table_size].dest[0] = fakeIP[0];
    routing_table[table_size].dest[1] = fakeIP[1];
    routing_table[table_size].dest[2] = fakeIP[2];
    routing_table[table_size].dest[3] = fakeIP[3];

    /* set the next hop address */
    routing_table[table_size].next[0] = fakeIP[0];
    routing_table[table_size].next[1] = fakeIP[1];
    routing_table[table_size].next[2] = fakeIP[2];
    routing_table[table_size].next[3] = fakeIP[3];

    /* set the actual port for the next hop */
    routing_table[table_size].next_hop = myaddr;

    /* set the distance for the destination */
    routing_table[table_size].distance = 1;
    table_size++;

}

/* Function to parse 1 frame from a file */
bool parse_frame(Frame* f, FILE *file_ptr,
                 unsigned char* buffer, int bytes_read) {

    /* declare variables */
    unsigned char c;
    int byte_size = sizeof(c);
    Frame* frame = f;
    frame->read_addr4 = false;
    FILE* fptr;

    /* use the file pointer parameter if it exists */
    if (file_ptr != NULL) {
        fptr = file_ptr;

        /* skip the PLCP Preamble and PLCP Header */
        for (int i = 0; i < 24; i++)  {
            if (fread(&c, byte_size, 1, fptr) == 0) return false;
        }
    } else {

        /* open the buffer for reading */
        fptr = fmemopen(buffer, bytes_read, "rb");
    }

    /*** IF BYTE CANNOT BE READ RETURN FALSE (EOF) ***/
    /* read the frame control */
    for (int i = 0; i < 2; i++) {
        if (fread(&frame->frame_control[i],
            byte_size, 1, fptr) == 0) return false;
    }

    /* process the frame control information */
    frame->to_ds = f->frame_control[1] & 0x01;
    frame->from_ds = (f->frame_control[1] >> 1) & 0x01;

    /* set true if addr4 exists */
    if (frame->to_ds == 1 && f->from_ds == 1) {
        frame->read_addr4 = true;
    }

    /* read the duration id */
    for (int i = 0; i < 2; i++) {
        if (fread(&frame->duration_id[i],
            byte_size, 1, fptr) == 0) return false;
    }

    /* read addr1 */
    for (int i = 0; i < 6; i++) {
        if (fread(&frame->addr1[i], byte_size, 1, fptr) == 0) return false;
    }

    /* read addr2 */
    for (int i = 0; i < 6; i++) {
        if (fread(&frame->addr2[i], byte_size, 1, fptr) == 0) return false;
    }

    /* read addr3 */
    for (int i = 0; i < 6; i++) {
        if (fread(&frame->addr3[i], byte_size, 1, fptr) == 0) return false;
    }

    /* read the sequence control */
    for (int i = 0; i < 2; i++) {
        if (fread(&frame->sequence_control[i],
            byte_size, 1, fptr) == 0) return false;
    }

    /* read addr4 if it exists */
    if (frame->read_addr4) {
        for (int i = 0; i < 6; i++) {
            if (fread(&frame->addr4[i], byte_size, 1, fptr) == 0) return false;
        }
    }

    /* set the source address */
    if (frame->to_ds == 0 && frame->from_ds == 0) {
        for (int i = 0; i < 6; i++) frame->src_addr[i] = frame->addr2[i];
    } else if (frame->to_ds == 0 && frame->from_ds == 1) {
        for (int i = 0; i < 6; i++) frame->src_addr[i] = frame->addr3[i];
    } else if (frame->to_ds == 1 && frame->from_ds == 0) {
       for (int i = 0; i < 6; i++) frame->src_addr[i] = frame->addr2[i];
    } else if (frame->to_ds == 1 && frame->from_ds == 1) {
        for (int i = 0; i < 6; i++) frame->src_addr[i] = frame->addr4[i];
    }

    /* set the destination address */
    if (frame->to_ds == 0 && frame->from_ds == 0) {
        for (int i = 0; i < 6; i++) frame->dest_addr[i] = frame->addr1[i];
    } else if (frame->to_ds == 0 && frame->from_ds == 1) {
        for (int i = 0; i < 6; i++) frame->dest_addr[i] = frame->addr1[i];
    } else if (frame->to_ds == 1 && frame->from_ds == 0) {
       for (int i = 0; i < 6; i++) frame->dest_addr[i] = frame->addr3[i];
    } else if (frame->to_ds == 1 && frame->from_ds == 1) {
        for (int i = 0; i < 6; i++) frame->dest_addr[i] = frame->addr3[i];
    }

    /* read the llc */
    for (int i = 0; i < 3; i++) {
        if (fread(&frame->llc[i], byte_size, 1, fptr) == 0) return false;
    }

    /* read the org code */
    for (int i = 0; i < 3; i++) {
        if (fread(&frame->org_code[i], byte_size, 1, fptr) == 0) return false;
    }

    /* read the type */
    for (int i = 0; i < 2; i++) {
        if (fread(&frame->type[i], byte_size, 1, fptr) == 0) return false;
    }

    /* begin to read the MAC client data */
    if (fread(&c, byte_size, 1, fptr) == 0) return false;
    frame->mac_data.version = (c >> 4) & 0x0f;

    /* calculate the length of the packet header */
    frame->mac_data.ihl = c & 0x0f;
    int header_length = (int)frame->mac_data.ihl;
    frame->mac_data.header_length = header_length * 4;

    /* read the mac type of service */
    if (fread(&frame->mac_data.type_of_service,
        byte_size, 1, fptr) == 0) return false;

    /* calculate the packet length */
    if (fread(&frame->mac_data.length[0],
        byte_size, 1, fptr) == 0) return false;

    int packet_length = (int)(frame->mac_data.length[0] << 8);

    if (fread(&frame->mac_data.length[1],
        byte_size, 1, fptr) == 0) return false;

    packet_length += (int)frame->mac_data.length[1];
    frame->mac_data.total_packet_length = packet_length;

    /* read the mac identification */
    for (int i = 0; i < 2; i++) if (fread(&frame->mac_data.identification[i],
         byte_size, 1, fptr) == 0) return false;

    /* read the flags and fragment offset */
    if (fread(&c, byte_size, 1, fptr) == 0) return false;

    frame->mac_data.flags = (c >> 5) & 0x07;
    frame->mac_data.fragment_offset[0] = c & 0x1f;
    if (fread(&frame->mac_data.fragment_offset[1],
        byte_size, 1, fptr) == 0) return false;

    /* read the time to live */
    if (fread(&frame->mac_data.time_to_live,
        byte_size, 1, fptr) == 0) return false;

    /* read the protocol */
    if (fread(&frame->mac_data.protocol, byte_size, 1, fptr) == 0) return false;

    /* read the header checksum */
    for (int i = 0; i < 2; i++) if (fread(&frame->mac_data.header_checksum[i],
         byte_size, 1, fptr) == 0) return false;

    /* read the source address */
    for (int i = 0; i < 4; i++) if (fread(&frame->mac_data.source_addr[i],
         byte_size, 1, fptr) == 0) return false;

    /* read the destination address */
    for (int i = 0; i < 4; i++) if (fread(&frame->mac_data.dest_addr[i],
         byte_size, 1, fptr) == 0) return false;

    /* read the options if there are any */
    if ((header_length - 20) > 0) {
        int bytes = header_length - 20;

        /* round up to 4 for a complete header line */
        while (bytes % 4 != 0) bytes++;

        /* allocate space for the amount of options present in the packet */
        frame->mac_data.options = (unsigned char*)malloc(sizeof(unsigned char)
                                   *bytes);
        f->mac_data.num_of_options = bytes;

        /* read the options from the stream */
        for (int i = 0; i < bytes; i++) if (fread(&frame->mac_data.options[i],
             byte_size, 1, fptr) == 0) return false;

    } else {

        /* set no options for the packet */
        frame->mac_data.options = (unsigned char*)malloc(sizeof(unsigned char)
                                   *1);
        frame->mac_data.options[0] = 0x00;
        f->mac_data.num_of_options = 0;
    }

    /* read the packet's data */
    int data_size = packet_length - (header_length * 4);
    frame->mac_data.data = (unsigned char*)malloc(sizeof(unsigned char*)
                            *data_size);

    for (int i = 0; i < data_size; i++) if (fread(&frame->mac_data.data[i],
         byte_size, 1, fptr) == 0) return false;

    /* read the frame check sequence */
    for (int i = 0; i < 4; i++) if (fread(&frame->frame_check_sequence[i],
         byte_size, 1, fptr) == 0) return false;

    /* calculate the total frame length */
    frame->total_frame_length = frame->mac_data.total_packet_length + 36;
    if (frame->read_addr4) frame->total_frame_length += 4;

    /* fill the frame data */
    fill_frame_data(frame);

    /* return true if frame is successfully read */
    return true;
}

/* Function to print 1 frame */
void print_frame(Frame* f) {

    /*** WLAN SECTION ***/
    printf("WLAN:   ----- WLAN HEADER -----\nWLAN:\nWLAN:   Packet size :"
           " %d bytes\n", f->total_frame_length);

    /* select the destination address using to_ds and from_ds */
    printf("WLAN:   Destination : ");
    if (f->to_ds == 0 && f->from_ds == 0) {
        printf("%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", f->addr1[0],
        f->addr1[1], f->addr1[2], f->addr1[3], f->addr1[4], f->addr1[5]);
    } else if (f->to_ds == 0 && f->from_ds == 1) {
        printf("%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", f->addr1[0],
        f->addr1[1], f->addr1[2], f->addr1[3], f->addr1[4], f->addr1[5]);
    } else if (f->to_ds == 1 && f->from_ds == 0) {
        printf("%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", f->addr3[0],
        f->addr3[1], f->addr3[2], f->addr3[3], f->addr3[4], f->addr3[5]);
    } else if (f->to_ds == 1 && f->from_ds == 1) {
        printf("%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", f->addr3[0],
        f->addr3[1], f->addr3[2], f->addr3[3], f->addr3[4], f->addr3[5]);
    }

    /* select the source address using to_ds and from_ds */
    printf("WLAN:   Source      : ");
    if (f->to_ds == 0 && f->from_ds == 0) {
        printf("%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", f->addr2[0],
        f->addr2[1], f->addr2[2], f->addr2[3], f->addr2[4], f->addr2[5]);
    } else if (f->to_ds == 0 && f->from_ds == 1) {
        printf("%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", f->addr3[0],
        f->addr3[1], f->addr3[2], f->addr3[3], f->addr3[4], f->addr3[5]);
    } else if (f->to_ds == 1 && f->from_ds == 0) {
        printf("%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", f->addr2[0],
        f->addr2[1], f->addr2[2], f->addr2[3], f->addr2[4], f->addr2[5]);
    } else if (f->to_ds == 1 && f->from_ds == 1) {
        printf("%02hhX-%02hhX-%02hhX-%02hhX-%02hhX-%02hhX\n", f->addr4[0],
        f->addr4[1], f->addr4[2], f->addr4[3], f->addr4[4], f->addr4[5]);
    }

    /* print the type */
    printf("WLAN:   Type        : %02hhX%02hhX", f->type[0], f->type[1]);
    if (f->type[0] == 0x08 && f->type[1] == 0x00) printf(" (IP)\n");
    else printf(" (UNKNOWN)\n");

    /*** IP SECTION ***/
    printf("IP:     ----- IP HEADER -----\nIP:\nIP:     Version = %d\n",
          (int)f->mac_data.version);
    printf("IP:     Header length = %d bytes\n", f->mac_data.header_length);
    printf("IP:     Type of service = 0x%02hhX\n", f->mac_data.type_of_service);
    printf("IP:     Total length = %d bytes\n",
           f->mac_data.total_packet_length);

    /* calculate the id */
    int id = (int)(f->mac_data.identification[0] << 8)
           + (int)f->mac_data.identification[1];

    printf("IP:     Identification = %d\n", id);

    printf("IP:     Flags = 0x%hhX\n", f->mac_data.flags);

    /* calculate the fragment offset */
    int frag_offset = (int)(f->mac_data.fragment_offset[0] << 8)
                    + (int)f->mac_data.fragment_offset[1];

    printf("IP:     Fragment offset = %d bytes\n", frag_offset);

    printf("IP:     Time to live = %d seconds/hops\n",
           f->mac_data.time_to_live);

    printf("IP:     Protocol = %d\n", f->mac_data.protocol);
    printf("IP:     Header checksum = 0x%02hhX%02hhX\n",
           f->mac_data.header_checksum[0], f->mac_data.header_checksum[1]);

    /* get the IP packet source address */
    int d0 = (int)f->mac_data.source_addr[0];
    int d1 = (int)f->mac_data.source_addr[1];
    int d2 = (int)f->mac_data.source_addr[2];
    int d3 = (int)f->mac_data.source_addr[3];
    printf("IP:     Source address = %d.%d.%d.%d\n", d0, d1, d2, d3);

    /* get the IP packet destination address */
    d0 = (int)f->mac_data.dest_addr[0];
    d1 = (int)f->mac_data.dest_addr[1];
    d2 = (int)f->mac_data.dest_addr[2];
    d3 = (int)f->mac_data.dest_addr[3];
    printf("IP:     Destination address = %d.%d.%d.%d\n", d0, d1, d2, d3);
    printf("IP:     ");

    /* print the options (if there are any) */
    if (f->mac_data.options[0] == 0x00) {
        printf("No options");
    } else {
        printf("0x%02hhX", f->mac_data.options[0]);
        for (int i = 1; i < f->mac_data.num_of_options; i++) {
            if (f->mac_data.options[i] != 0x00) printf(", 0x%02hhX",
                f->mac_data.options[i]);
        }
    }

    /*** HEX DUMP SECTION ***/
    int row = 0;
    int hex_vals[16];
    printf("\n%03d0 %02hhX ", row, f->frame_data[0]);

    /* print the hex values (and their characters) in rows of 16 bytes */
    for (int i = 1, j = 0; i < f->total_frame_length; i++, j++) {

        /* if < 16, print on the same row, else print a new row */
        if (i % 16 != 0) {
            printf("%02hhX ", f->frame_data[i]);
            hex_vals[j] = (int) f->frame_data[i];
        } else {
            hex_vals[j] = (int) f->frame_data[i];
            j = 0;

            /* print the first 8 hex values as characters */
            for (int k = 0; k < 8; k++) {
                if (hex_vals[k] > 32 && hex_vals[k] < 126) {
                    printf("%c", hex_vals[k]);
                } else printf(".");
            }

            printf(" ");

            /* print the second 8 hex values as characters */
            for (int k = 0; k < 8; k++) {
                if (hex_vals[k + 8] > 32 && hex_vals[k + 8] < 126) {
                    printf("%c", hex_vals[k + 8]);
                } else printf(".");
            }

            /* print next row header */
            row++;
            printf("\n%03d0 %02hhX ", row, f->frame_data[i]);
        }
    }

    /* fill the last row with 00 (to make 16 bytes in the row) */
    if (f->total_frame_length % 16 != 0) {
        for (int i = 0; i < (16 - f->total_frame_length % 16); i++) {
            printf("%02hhX ", 0x00);
            hex_vals[i + (f->total_frame_length % 16)] = 0;
        }

        /* print the first 8 hex values as characters */
        for (int k = 0; k < 8; k++) {
            if (hex_vals[k] > 32 && hex_vals[k] < 126) {
                    printf("%c", hex_vals[k]);
            } else printf(".");
        }

        printf(" ");

        /* print the second 8 hex values as characters */
        for (int k = 0; k < 8; k++) {
            if (hex_vals[k + 8] > 32 && hex_vals[k + 8] < 126) {
                printf("%c", hex_vals[k + 8]);
            } else printf(".");
        }
    }

    printf("\n");
}

/* Function to build the frame data from its fields
 * Frame data is just all bytes in the frame */
void fill_frame_data(Frame* f) {

    /* allocate memory for the frame data */
    f->frame_data = (unsigned char*)malloc(sizeof(unsigned char)
                    *f->total_frame_length);
    int pos = 0;

    /* insert the frame data using the fields of the frame */
    for (int i = 0; i < 2; i++, pos++) f->frame_data[pos] = f->frame_control[i];
    for (int i = 0; i < 2; i++, pos++) f->frame_data[pos] = f->duration_id[i];
    for (int i = 0; i < 6; i++, pos++) f->frame_data[pos] = f->addr1[i];
    for (int i = 0; i < 6; i++, pos++) f->frame_data[pos] = f->addr2[i];
    for (int i = 0; i < 6; i++, pos++) f->frame_data[pos] = f->addr3[i];
    for (int i = 0; i < 2; i++, pos++) {
        f->frame_data[pos] = f->sequence_control[i];
    }

    /* if addr4 exists, add it to the frame data */
    if (f->read_addr4) {
        for (int i = 0; i < 2; i++, pos++) f->frame_data[pos] = f->addr4[i];
    }

    /* get the llc, org code, and type */
    for (int i = 0; i < 3; i++, pos++) f->frame_data[pos] = f->llc[i];
    for (int i = 0; i < 3; i++, pos++) f->frame_data[pos] = f->org_code[i];
    for (int i = 0; i < 2; i++, pos++) f->frame_data[pos] = f->type[i];

    /*** insert the MAC Client Data into the frame data ***/
    /* get the version and ihl */
    f->frame_data[pos] = (f->mac_data.version << 4) | f->mac_data.ihl;
    pos++;

    /* get the type of service */
    f->frame_data[pos] = f->mac_data.type_of_service;
    pos++;

    /* get the length and identification of the MAC client data */
    for (int i = 0; i < 2; i++, pos++) {
        f->frame_data[pos] = f->mac_data.length[i];
    }

    for (int i = 0; i < 2; i++, pos++) {
        f->frame_data[pos] = f->mac_data.identification[i];
    }

    /* get the fragment offset */
    f->frame_data[pos] = (f->mac_data.flags << 5)
                         | f->mac_data.fragment_offset[0];
    pos++;
    f->frame_data[pos] = f->mac_data.fragment_offset[1];
    pos++;

    /* get the time to live */
    f->frame_data[pos] = f->mac_data.time_to_live;
    pos++;

    /* get the protocol */
    f->frame_data[pos] = f->mac_data.protocol;
    pos++;

    /* get the header checksum, source address,
     * destination address, and options */
    for (int i = 0; i < 2; i++, pos++) {
        f->frame_data[pos] = f->mac_data.header_checksum[i];
    }

    for (int i = 0; i < 4; i++, pos++) {
        f->frame_data[pos] = f->mac_data.source_addr[i];
    }

    for (int i = 0; i < 4; i++, pos++) {
        f->frame_data[pos] = f->mac_data.dest_addr[i];
    }

    for (int i = 0; i < f->mac_data.num_of_options; i++, pos++) {
        f->frame_data[pos] = f->mac_data.options[i];
    }

    /* get the MAC payload data */
    int data_length = f->mac_data.total_packet_length
                    - f->mac_data.header_length;

    for (int i = 0; i < data_length; i++, pos++) {
        f->frame_data[pos] = f->mac_data.data[i];
    }

    /* get the frame check sequence */
    for (int i = 0; i < 4; i++, pos++) {
        f->frame_data[pos] = f->frame_check_sequence[i];
    }
}
