#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>


/**
 * Joseph McGill
 * Fall 2016
 * This program reads the frames of the input_data.bin file. It is useful to
 * see what the input data is.
 *
 * The program needs to be compiled with gcc frame_reader.c
 * and can be ran with ./a.out input_data.bin
 * */

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

/* Function prototypes */
bool parse_frame(Frame* f, FILE *file_ptr);
void print_frame(Frame* f);
void fill_frame_data(Frame* f);

/* Main function */
int main(int argc, char* argv[]) {

    /* open the input file for reading */
    FILE *file_ptr;
    file_ptr = fopen(argv[1], "rb");

    /* arbitrarily sized Frame array */
    Frame frames[64];
    int frame_count = 0;

    /* parse the frames until a malformed frame is found (or EOF) */
    while (parse_frame(&frames[frame_count], file_ptr) != false) {
        frame_count++;

        /* advance the file 12 bytes (space separating frames) */
        fseek(file_ptr, 12, SEEK_CUR);
    }

    printf("\nFrame count: %d\n", frame_count);
    /* print the frames that were read in */
    for (int i = 0; i < frame_count; i++) print_frame(&frames[i]);

    /* free the memory allocated */
    for (int i = 0; i < frame_count; i++) {
        free(frames[i].mac_data.options);
        free(frames[i].mac_data.data);
        free(frames[i].frame_data);
    }

    /* exit the program */
    return 0;
}

/* Function to parse 1 frame */
bool parse_frame(Frame* f, FILE *file_ptr) {

    /* declare variables */
    unsigned char c;
    int byte_size = sizeof(c);
    FILE *fptr = file_ptr;
    Frame* frame = f;
    frame->read_addr4 = false;

    /*** IF BYTE CANNOT BE READ RETURN FALSE (EOF) ***/

    /* skip the PLCP Preamble and PLCP Header */
    for (int i = 0; i < 24; i++)  if (fread(&c, byte_size, 1,
                                      fptr) == 0) return false;

    /* read the frame control */
    for (int i = 0; i < 2; i++) if (fread(&frame->frame_control[i],
                                byte_size, 1, fptr) == 0) return false;

    /* process the frame control information */
    frame->to_ds = f->frame_control[1] & 0x01;
    frame->from_ds = (f->frame_control[1] >> 1) & 0x01;

    /* set true if addr4 exists */
    if (frame->to_ds == 1 && f->from_ds == 1) {
        frame->read_addr4 = true;
    }

    /* read the duration id */
    for (int i = 0; i < 2; i++) if (fread(&frame->duration_id[i],
                                    byte_size, 1, fptr) == 0) return false;

    /* read addr1 */
    for (int i = 0; i < 6; i++) if (fread(&frame->addr1[i],
                                    byte_size, 1, fptr) == 0) return false;

    /* read addr2 */
    for (int i = 0; i < 6; i++) if (fread(&frame->addr2[i],
                                    byte_size, 1, fptr) == 0) return false;

    /* read addr3 */
    for (int i = 0; i < 6; i++) if (fread(&frame->addr3[i],
                                    byte_size, 1, fptr) == 0) return false;

    /* read the sequence control */
    for (int i = 0; i < 2; i++) if (fread(&frame->sequence_control[i],
                                    byte_size, 1, fptr) == 0) return false;

    /* read addr4 if it exists */
    if (frame->read_addr4) {
        for (int i = 0; i < 6; i++) if (fread(&frame->addr4[i],
                                        byte_size, 1, fptr) == 0) return false;
    }

    /* read the llc */
    for (int i = 0; i < 3; i++) if (fread(&frame->llc[i],
                                    byte_size, 1, fptr) == 0) return false;

    /* read the org code */
    for (int i = 0; i < 3; i++) if (fread(&frame->org_code[i],
                                    byte_size, 1, fptr) == 0) return false;

    /* read the type */
    for (int i = 0; i < 2; i++) if (fread(&frame->type[i],
                                    byte_size, 1, fptr) == 0) return false;

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
    if (fread(&frame->mac_data.protocol,
        byte_size, 1, fptr) == 0) return false;

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
           "%d bytes\n", f->total_frame_length);

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
