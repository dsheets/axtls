
#define OPENSSL_CTX_ATTR  ((OPENSSL_CTX *)ssl_ctx->bonus_attr)

#define STACK_OF(TOK) STACK_OF_##TOK##S *

typedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata);

typedef struct ssl_method_st SSL_METHOD;
struct ssl_method_st {
  const SSL_METHOD *(*ctor)(void);
};

typedef void BIO;

typedef struct x509_store_ctx_st X509_STORE_CTX;
struct x509_store_ctx_st {

};

typedef void * STACK_OF_X509_NAMES;

typedef void X509;

const SSL_METHOD *SSLv3_method(void);		/* SSLv3 */
const SSL_METHOD *SSLv3_server_method(void);	/* SSLv3 */
const SSL_METHOD *SSLv3_client_method(void);	/* SSLv3 */

const SSL_METHOD *SSLv23_method(void);	/* SSLv3 but can rollback to v2 */
const SSL_METHOD *SSLv23_server_method(void);	/* SSLv3 but can rollback to v2 */
const SSL_METHOD *SSLv23_client_method(void);	/* SSLv3 but can rollback to v2 */

const SSL_METHOD *TLSv1_method(void);		/* TLSv1.0 */
const SSL_METHOD *TLSv1_server_method(void);	/* TLSv1.0 */
const SSL_METHOD *TLSv1_client_method(void);	/* TLSv1.0 */


int  SSL_library_init(void );
void SSL_load_error_strings(void );
SSL_CTX *SSL_CTX_new(const SSL_METHOD *meth);
void	SSL_CTX_free(SSL_CTX *);
int	SSL_use_certificate_file(SSL *ssl, const char *file, int type);
int	SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, const unsigned char *d);
int	SSL_CTX_set_session_id_context(SSL_CTX *ctx,const unsigned char *sid_ctx,
				       unsigned int sid_ctx_len);
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
int	SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file); /* PEM type */
void SSL_CTX_set_verify(SSL_CTX *ctx,int mode,
			int (*callback)(int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
	const char *CApath);
STACK_OF(X509_NAME) *SSL_load_client_CA_file(const char *file);
void SSL_set_client_CA_list(SSL *s, STACK_OF(X509_NAME) *name_list);
void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);
int	SSL_CTX_set_cipher_list(SSL_CTX *,const char *str);

                    /* SSL_CTX_set_options macro? */

SSL *	SSL_new(SSL_CTX *ctx);
int	SSL_set_fd(SSL *s, int fd);
int 	SSL_accept(SSL *ssl);
int 	SSL_connect(SSL *ssl);
void	SSL_free(SSL *ssl);
int 	SSL_read(SSL *ssl,void *buf,int num);
int 	SSL_peek(SSL *ssl,void *buf,int num);
int 	SSL_write(SSL *ssl,const void *buf,int num);
int SSL_shutdown(SSL *s);
void	SSL_set_bio(SSL *s, BIO *rbio,BIO *wbio);
long SSL_get_verify_result(const SSL *ssl);
int SSL_state(const SSL *ssl);
X509 *	SSL_get_peer_certificate(const SSL *s);

                    /* SSL_clear macro? */

int	SSL_get_error(const SSL *s,int ret_code);
SSL_SESSION *SSL_get1_session(SSL *ssl); /* obtain a reference count */
int	SSL_set_session(SSL *to, SSL_SESSION *session);
void	SSL_SESSION_free(SSL_SESSION *ses);
