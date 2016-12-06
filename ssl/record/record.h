



typedef struct ssl3_buffer_st {
    /* at least SSL3_RT_MAX_PACKET_SIZE bytes, see ssl3_setup_buffers() */
    unsigned char *buf;
    /* default buffer size (or 0 if no default set) */
    size_t default_len;
    /* buffer size */
    size_t len;
    /* where to 'copy from' */
    int offset;
    /* how many bytes left */
    int left;
} SSL3_BUFFER;

#define SEQ_NUM_SIZE                            8

typedef struct ssl3_record_st {
    /* Record layer version */
    /* r */
    int rec_version;
    /* type of record */
    /* r */
    int type;
    /* How many bytes available */
    /* rw */
    unsigned int length;
    /*
     * How many bytes were available before padding was removed? This is used
     * to implement the MAC check in constant time for CBC records.
     */
    /* rw */
    unsigned int orig_len;
    /* read/write offset into 'buf' */
    /* r */
    unsigned int off;
    /* pointer to the record data */
    /* rw */
    unsigned char *data;
    /* where the decode bytes are */
    /* rw */
    unsigned char *input;
    /* only used with decompression - malloc()ed */
    /* r */
    unsigned char *comp;
    /* Whether the data from this record has already been read or not */
    /* r */
    unsigned int read;

} SSL3_RECORD;

typedef struct record_pqueue_st {
    unsigned short epoch;
    struct pqueue_st *q;
} record_pqueue;



typedef struct record_layer_st {
    /* The parent SSL structure */
    SSL *s;
    /*
     * Read as many input bytes as possible (for
     * non-blocking reads)
     */
    int read_ahead;
    /* where we are when reading */
    int rstate;
    /* How many pipelines can be used to read data */
    unsigned int numrpipes;
    /* How many pipelines can be used to write data */
    unsigned int numwpipes;
    /* read IO goes into here */
    SSL3_BUFFER rbuf;
    /* write IO goes into here */
    SSL3_BUFFER wbuf[SSL_MAX_PIPELINES];
    /* each decoded record goes in here */
    SSL3_RECORD rrec[SSL_MAX_PIPELINES];
    /* used internally to point at a raw packet */
    unsigned char *packet;
    unsigned int packet_length;
    /* number of bytes sent so far */
    unsigned int wnum;
    /*
     * storage for Alert/Handshake protocol data received but not yet
     * processed by ssl3_read_bytes:
     */
    unsigned char alert_fragment[2];
    unsigned int alert_fragment_len;
    unsigned char handshake_fragment[4];
    unsigned int handshake_fragment_len;
    /* The number of consecutive empty records we have received */
    unsigned int empty_record_count;
    /* partial write - check the numbers match */
    /* number bytes written */
    int wpend_tot;
    int wpend_type;
    /* number of bytes submitted */
    int wpend_ret;
    const unsigned char *wpend_buf;
    unsigned char read_sequence[SEQ_NUM_SIZE];
    unsigned char write_sequence[SEQ_NUM_SIZE];
    /* Set to true if this is the first record in a connection */
    unsigned int is_first_record;
} RECORD_LAYER;

/*****************************************************************************
 *                                                                           *
 * The following macros/functions represent the libssl internal API to the   *
 * record layer. Any libssl code may call these functions/macros             *
 *                                                                           *
 *****************************************************************************/

#define MIN_SSL2_RECORD_LEN     9

#define RECORD_LAYER_set_read_ahead(rl, ra)     ((rl)->read_ahead = (ra))
#define RECORD_LAYER_get_read_ahead(rl)         ((rl)->read_ahead)
#define RECORD_LAYER_get_packet(rl)             ((rl)->packet)
#define RECORD_LAYER_get_packet_length(rl)      ((rl)->packet_length)
#define RECORD_LAYER_add_packet_length(rl, inc) ((rl)->packet_length += (inc))


void RECORD_LAYER_init(RECORD_LAYER *rl, SSL *s);
void RECORD_LAYER_clear(RECORD_LAYER *rl);
void RECORD_LAYER_release(RECORD_LAYER *rl);
int RECORD_LAYER_read_pending(const RECORD_LAYER *rl);
int RECORD_LAYER_write_pending(const RECORD_LAYER *rl);
int RECORD_LAYER_set_data(RECORD_LAYER *rl, const unsigned char *buf, int len);
void RECORD_LAYER_reset_read_sequence(RECORD_LAYER *rl);
void RECORD_LAYER_reset_write_sequence(RECORD_LAYER *rl);
int RECORD_LAYER_is_sslv2_record(RECORD_LAYER *rl);
unsigned int RECORD_LAYER_get_rrec_length(RECORD_LAYER *rl);

int ssl3_pending(const SSL *s);
int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);
int do_ssl3_write(SSL *s, int type, const unsigned char *buf, unsigned int *pipelens, unsigned int numpipes, int create_empty_fragment);
int ssl3_read_bytes(SSL *s, int type, int *recvd_type, unsigned char *buf, int len, int peek);
int ssl3_setup_buffers(SSL *s);
int ssl3_enc(SSL *s, SSL3_RECORD *inrecs, unsigned int n_recs, int send);
int n_ssl3_mac(SSL *ssl, SSL3_RECORD *rec, unsigned char *md, int send);
int ssl3_write_pending(SSL *s, int type, const unsigned char *buf, unsigned int len);
int tls1_enc(SSL *s, SSL3_RECORD *recs, unsigned int n_recs, int send);
int tls1_mac(SSL *ssl, SSL3_RECORD *rec, unsigned char *md, int send);



