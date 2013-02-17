#include "server.h"

int main (int argc, char* argv[])
{
    /*
     * general definitions
     */
    FILE *config_file;
    int retv;
    int start_http, start_https;
    char *c_token;

    /* read options */
    if (argc > 1) {
        if (!strcmp("https", argv[0])) {
            printf("https\n");
            start_http = 0;
            start_https = 1;
        } else if (!strcmp("http", argv[0])) {
            printf("http\n");
            start_http = 1;
            start_https = 0;
        } else {
            printf("Incorrect option, usage:\n");
            printf("server - starts both servers\n");
            printf("server http - starts http server only");
            printf("server https - starts https server only");
        }
    } else {
        printf("oba\n");
        start_http = 1;
        start_https = 1;
    }

    GDBM_FILE database = gdbm_open("session.db", 0, GDBM_WRCREAT | GDBM_NOMMAP , S_IRWXU, NULL);
    gdbm_close(database);
    /* read configuration file
     * recognized tokens:
     *
     * http:
     * HTTP_PORT        listening port for http server
     * HTTP_MAX_CONN    maximum number of simultaneous connections
     * HTTP_DIR     http resources directory
     * HTTP_GET     script invoked for GET method
     * HTTP_POST        script invoked for POST method
     *
     * https:
     * HTTPS_PORT       listening port for http server
     * HTTPS_MAX_CONN   maximum number of simultaneous connections
     * HTTPS_DIR        http resources directory
     * HTTPS_GET        script invoked for GET method
     * HTTPS_POST       script invoked for POST method
     * HTTPS_CERT       certificate file
     * HTTPS_KEY        private key file
     * HTTPS_PASS       password for private key
     * HTTP_METH        https method (SSLv2, SSLv23, SSLv3, TLSv1)
     */
    /*
    config_file = fopen("server.conf", "r");
    setvbuf(config_file, NULL, _IOFBF, 256);
    if (unlikely(config_file < 0)) {
        perror("Cannot read configuration file (server.conf)");
        exit(EXIT_FAILURE);
    }
    c_token = strtok(config_file, " \n");
    
    while(!feof(config_file)) {
        switch(strcmp(
        c_token = strtok(NULL, " \n");
    }
    */
    http_s.port = 80;
    http_s.conn_num = 32;
    http_s.dir = "http";
    http_s.get_script = "get.sh";
    http_s.post_script = "post.sh";

    https_s.port = 443;
    https_s.conn_num = 32;
    https_s.dir = "https";
    https_s.get_script = "get.sh";
    https_s.post_script = "post.sh";

    https_d.certificate_file = "mycert.pem";
    https_d.key_file = "mykey.pem";
    https_d.key_password = "test";
    https_d.method = "TLSv1";
    https_d.sess_db_name = "session.db";

    https_d.admin_username = "test";
    https_d.admin_password = "test";
    https_d.guest_username = "test";
    https_d.guest_password = "test";

    if (start_http && start_https) {
        if (fork()) {
            printf("http server working\n");
            http_server();  
        } else {
            https_server();
        }
    } else {
        if (start_http) http_server();
        if (start_https) https_server();
    }
}

void https_server()
{
    int retv;
    /*
     * https server definitions
     */
    struct sockaddr_in addr;
    int listen_sock, conn_sock;
    /* openssl library definitions */
    const SSL_METHOD *ssl_method;
    SSL_CTX *ctx;

    /* openssl initialization */
    SSL_library_init();
    if (!strcmp("TLSv1", https_d.method)) {
        ctx = SSL_CTX_new(TLSv1_server_method());
    } else if (!strcmp("SSLv3", https_d.method)) {
        ctx = SSL_CTX_new(SSLv3_server_method());
    } else if (!strcmp("SSLv23", https_d.method)) {
        ctx = SSL_CTX_new(SSLv23_server_method());
    }
    if (unlikely(ctx == NULL)) {
        perror("Cannot create CTX object!");
        exit(EXIT_FAILURE);
    }
    SSL_CTX_set_default_passwd_cb(ctx, get_passwd);
    if (unlikely(!SSL_CTX_use_certificate_file(ctx, https_d.certificate_file, SSL_FILETYPE_PEM))) {
        perror("Cannot load certificate file!");
        exit(EXIT_FAILURE);
    }
    if (unlikely(!SSL_CTX_use_PrivateKey_file(ctx, https_d.key_file, SSL_FILETYPE_PEM))) {
        perror("Cannot load key file");
        exit(EXIT_FAILURE);
    }
    if (unlikely(!SSL_CTX_check_private_key(ctx))) {
        perror("Key is not compatible with the certificate!");
        exit(EXIT_FAILURE);
    }
    /* create socket */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(https_s.port);
    addr.sin_addr.s_addr = INADDR_ANY;
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    retv = bind(listen_sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
    if (unlikely(retv < 0)) {
        perror("Cannot bind to specified port!");
        exit(EXIT_FAILURE);
    }
    retv = listen(listen_sock, 32);
    if (unlikely(retv < 0)) {
        perror("Cannot liten on specified port!");
        exit(EXIT_FAILURE);
    }
    while (1) {
        conn_sock = accept(listen_sock, NULL, NULL);    
        if (listen_sock < 0) {
            perror("Cannot accept connection!");
            continue;
            /* save info in log */
        }
        if (fork()) {
            close(conn_sock);
        } else {
            https_service_conn(conn_sock, ctx);
        }
    }
    close(listen_sock);
    exit(EXIT_SUCCESS);
}

void http_server()
{
    /*
     * http server definitions
     */
    struct sockaddr_in addr;
    int listen_sock, conn_sock;
    int retv;
    /* create socket */
    addr.sin_family = AF_INET;
    addr.sin_port = htons(http_s.port);
    addr.sin_addr.s_addr = INADDR_ANY;
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    retv = bind(listen_sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
    if (unlikely(retv < 0)) {
        perror("Cannot bind to specified port!");
        exit(EXIT_FAILURE);
    }
    retv = listen(listen_sock, 32);
    if (unlikely(retv < 0)) {
        perror("Cannot liten on specified port!");
        exit(EXIT_FAILURE);
    }
    while (1) {
        conn_sock = accept(listen_sock, NULL, NULL);    
        if (listen_sock < 0) {
            perror("Cannot accept connection!");
            continue;
            /* save info in log */
        }
        if (fork()) {
            close(conn_sock);
        } else {
            http_service_conn(conn_sock);
        }
    }
    close(listen_sock);
    exit(EXIT_SUCCESS);
}

void https_service_conn(int conn_sock, SSL_CTX *ctx)
{
    char buf[MAX_BUF_LENGTH];
    int count, retv;
    struct message *msg;
    /* openssl library definitions */
    SSL* ssl;

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        perror("cannot create SSL object!");
        return;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_fd(ssl, conn_sock);
    SSL_set_accept_state(ssl);
    retv = SSL_accept(ssl);
    if (retv < 0) goto ERROR;
    
    count = SSL_read(ssl, buf, MAX_BUF_LENGTH-1);
    if (count < 0) goto ERROR;
    buf[count] = '\0';
    printf(buf);

    if (!strncmp(buf, "GET", 3)) {
        char url[256];
        strtok(buf, " ");
        strcpy(url, https_s.dir);
        strcat(url, strtok(NULL, " "));
        if (strcmp(url, "index.html")) {
            write_url_ssl(ssl, buf, url);
        } else if (strcmp(url, "guest_panel.html")) {
            if (check_privileges()) {
                write_url_ssl(ssl, buf, url);
            } else {
                write_404_ssl(ssl, buf, "<html><body>You don't have access! Go away!</body></html>");
            }
        } else if (strcmp(url, "admin_panel.html")) {
            if (check_privileges() == ADMIN_PRIV) {
                write_url_ssl(ssl, buf, url);
            } else {
                write_404_ssl(ssl, buf, "<html><body>You don't have access! Go away!</body></html>");
            }
        }
    }
    if (!strncmp(buf, "POST", 4)) {
        int i;
        char *tmp;
        char *password;
        char *username;
        int admin_login = 1;
        int guest_login = 1;
        char *ble = buf;
        if ((tmp = strstr(buf, "username")) != NULL) {
            if (strcmp("username", strtok(tmp, "=&"))) {
                admin_login = 0;
                guest_login = 0;
            }
            username = strtok(NULL, "=&");
            printf("user: %s\n", username);
            if (strcmp(username, https_d.admin_username)) admin_login = 0;
            if (strcmp(username, https_d.guest_username)) guest_login = 0;
            if (strcmp("password", strtok(NULL, "=&"))) {
                admin_login = 0;
                guest_login = 0;
            }
            password = strtok(NULL, "=&");
            printf("pass: %s\n", password);
            if (strcmp(password, https_d.admin_password)) admin_login = 0;
            if (strcmp(password, https_d.guest_password)) guest_login = 0;
            if (admin_login) {
                /*
                 * save session id with appropriate flag
                 */
                save_session(ssl, ADMIN_PRIV);
                write_url_ssl(ssl, buf, "admin_login.html");
            }
            if (guest_login) {
                /*
                 * save session id with appropriate flag
                 */
                save_session(ssl, GUEST_PRIV);
                write_url_ssl(ssl, buf, "guest_login.html");
            }
            if (!admin_login && !guest_login) {
                write_404_ssl(ssl, buf, "<html><body>Logging has failed! Go away!</body></html>");
            }
            //printf(buf);
        } else if ((tmp = strstr(buf, "killall")) != NULL) {
            /* killal has been issued */    
            if (check_privileges(ssl) == ADMIN_PRIV) {
                system("killall.sh");
            } else {
                write_404_ssl(ssl, buf, "<html><body>You cannot do that!Go away!</body></html>");
            }
        } else if ((tmp = strstr(buf, "poweroff")) != NULL) {
            if (check_privileges(ssl) == ADMIN_PRIV) {
                system("poweroff.sh");
            } else {
                write_404_ssl(ssl, buf, "<html><body>You cannot do that!Go away!</body></html>");
            }
        } else if ((tmp = strstr(buf, "something")) != NULL) {
            if (check_privileges(ssl) == ADMIN_PRIV) {
                system("something.sh");
            } else {
                write_404_ssl(ssl, buf, "<html><body>You cannot do that!Go away!</body></html>");
            }
        }    
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(conn_sock);
    exit(EXIT_SUCCESS);
ERROR:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(conn_sock);
    exit(EXIT_FAILURE);
}

void http_service_conn(int conn_sock)
{
    char buf[MAX_BUF_LENGTH];
    char *url = "http/index.html";
    write_url_sock(conn_sock, buf, url);
    close(conn_sock);
}

void save_session(SSL *ssl, int privilege)
{
    SSL_SESSION* session;
    const unsigned char *sess_id;
    int sess_id_len;
    GDBM_FILE database;
    datum key, data;

    session = SSL_get_session(ssl);
    sess_id = SSL_SESSION_get_id(session, &sess_id_len);
    /* write session to dbm */
    key.dptr = (char *)sess_id;
    key.dsize = strlen(key.dptr);
    database = gdbm_open(https_d.sess_db_name, 0, GDBM_WRITER | GDBM_NOMMAP , S_IRWXU, NULL);
    switch (privilege) {
    case ADMIN_PRIV:
        data.dptr = "ADMIN";
        data.dsize = strlen(data.dptr);
        gdbm_store(database, key, data, GDBM_REPLACE); 
        break;
    case GUEST_PRIV:
        data.dptr = "GUEST";
        data.dsize = strlen(data.dptr);
        gdbm_store(database, key, data, GDBM_REPLACE); 
        break;
    }
    gdbm_close(database);
    printf("session id: %s", sess_id);
}

int check_privileges(SSL *ssl)
{
    SSL_SESSION* session;
    const unsigned char *sess_id;
    int sess_id_len;
    GDBM_FILE database;
    datum key, data;
    int ret = 0;

    session = SSL_get_session(ssl);
    sess_id = SSL_SESSION_get_id(session, &sess_id_len);
    /* check session id in database */
    key.dptr = (char *)sess_id;
    key.dsize = strlen(key.dptr);
    database = gdbm_open(https_d.sess_db_name, 0, GDBM_READER | GDBM_NOMMAP, S_IRWXU, NULL);
    data = gdbm_fetch(database, key);
    if (data.dptr != NULL) {
        if (!strcmp(data.dptr, "ADMIN")) {
            ret = ADMIN_PRIV;
        } else if (!strcmp(data.dptr, "GUEST")) {
            ret = GUEST_PRIV;
        }
    }
    gdbm_close(database);
    printf("session id: %s", sess_id);
    return ret;
}

int write_url_ssl(SSL *ssl, char *buf, char *url)
{
    FILE *resource;
    int count;
    resource = fopen(url, "r");
    //printf("RES ASKED: %s\n", url);
    if (resource != NULL) {
        strcpy(buf, "HTTP/1.1 200 OK\n\n");
        SSL_write(ssl, buf, strlen(buf));
        printf(buf);
        do {
            count = fread(buf, sizeof(char), MAX_BUF_LENGTH, resource);
            SSL_write(ssl, buf, count);
            printf(buf);
        } while (count == MAX_BUF_LENGTH);
        fclose(resource);
    } else {
        write_404_ssl(ssl, buf, "<html><body>No resource</body></html>");
        printf(buf);
    }
}

int write_url_sock(int sock, char *buf, char *url)
{
    FILE *resource;
    int count;
    resource = fopen(url, "r");
    if (resource != NULL) {
        //strcpy(buf, "HTTP/1.1 200 OK\n\n");
        //send(sock, buf, strlen(buf), NULL);
        //printf(buf);
        do {
            count = fread(buf, sizeof(char), MAX_BUF_LENGTH, resource);
            send(sock, buf, count, 0);
            printf(buf);
        } while (count == MAX_BUF_LENGTH);
        fclose(resource);
    } else {
        //write_404_ssl(ssl, buf, "<html><body>No resource</body></html>");
        printf(buf);
    }
}

void write_200_ssl(SSL *ssl, char *buf, char *msg)
{
    strcpy(buf, "HTTP/1.1 200 OK\n\r\n\r");
    strcat(buf, msg);
    strcat(buf, "\n\r\n\r");
    SSL_write(ssl, buf, strlen(buf));
}

void write_404_ssl(SSL *ssl, char *buf, char *msg)
{
    strcpy(buf, "HTTP/1.1 404 Not Found\n\r\n\r");
    strcat(buf, msg);
    strcat(buf, "\n\r\n\r");
    SSL_write(ssl, buf, strlen(buf));
}

int get_passwd(char *buffer, int size, int rwflag, void *userdata)
{
    strcpy(buffer, https_d.key_password);
    return strlen(https_d.key_password);
}
