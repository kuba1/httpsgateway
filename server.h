#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <gdbm.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define MAX_BUF_LENGTH 2048

extern int gdbm_errno;
extern int errno;

#define ADMIN_PRIV 1
#define GUEST_PRIV 2

struct http_settings
{
	int port;
	int conn_num;
	char *dir;
	/* http handling scripts */
	char *get_script;
	char *post_script;
	/* http configuration */
} http_s, https_s; 

struct https_settings
{
	/* https files */
	char *certificate_file;
	char *key_file;
	char *key_password;
	/* https configuration */
	char *method;
    char *sess_db_name;
	/* user configuration */
	char *admin_username;
	char *admin_password;
	char *guest_username;
	char *guest_password;
} https_d;

void https_server();
void http_server();
void https_service_conn(int conn_sock, SSL_CTX *ctx);
void http_service_conn(int conn_sock);
int get_passwd(char *buffer, int size, int rwflag, void *userdata);
int write_url_ssl(SSL *ssl, char *buf, char *url);
int write_url_sock(int sock, char *buf, char *url);
void write_200_ssl(SSL *ssl, char *buf, char *msg);
void write_404_ssl(SSL *ssl, char *buf, char *msg);
void save_session(SSL *ssl, int privilege);
int check_privileges();
