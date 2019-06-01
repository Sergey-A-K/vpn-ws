#include "vpn-ws.h"

gnutls_certificate_credentials_t xcred;
// A very basic TLS client, with X.509 authentication and server certificate
// verification. Note that error recovery is minimal for simplicity.

#define CHECK(x) assert((x)>=0)

#define LOOP_CHECK(rval, cmd) do { rval = cmd; \
    } while(rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED); \
    assert(rval >= 0)

#ifdef GNUTLS_LOGLEVEL
static void gnutls_logger_cb(int level, const char *message) {
    if (strlen(message) < 1) fprintf(stderr, "D%d: empty debug message!\n", level);
    else fprintf(stderr, "D%d: %s", level, message);
}

// GnuTLS will call this function whenever there is a new audit log message.
static void gnutls_audit_cb(gnutls_session_t psess, const char* message) {
    (void) psess;
    fprintf(stderr, "Audit: %s", message);
}
#endif

ssize_t vpn_ws_ssl_write(gnutls_session_t session, uint8_t *buf, size_t len) {
    ssize_t ret;
    LOOP_CHECK(ret, gnutls_record_send(session, buf, len));
	if (ret == 0) { vpn_ws_log(" - Server has closed TLS connection on record_send\n"); return -1; }
	else if  (ret < 0 && gnutls_error_is_fatal(ret) == 0) { vpn_ws_log("*** record_send WARN: %s\n", gnutls_strerror(ret)); }
	else if (ret < 0) { vpn_ws_log(" - record_send ERR: %s\n", gnutls_strerror(ret)); return -1; }
	return ret;
}

ssize_t vpn_ws_ssl_read(gnutls_session_t session, uint8_t *buf, size_t len) {
    ssize_t ret;
    LOOP_CHECK(ret, gnutls_record_recv(session, buf, len));
	if (ret == 0) { vpn_ws_log(" - Server has closed TLS connection on record_recv\n"); return -1; }
	else if (ret < 0 && gnutls_error_is_fatal(ret) == 0) { vpn_ws_log("*** record_recv WARN: %s\n", gnutls_strerror(ret)); }
	else if (ret < 0) { vpn_ws_log("*** record_recv ERR: %s\n", gnutls_strerror(ret)); return -1; }
	return ret;
}

gnutls_session_t vpn_ws_ssl_handshake(vpn_ws_peer *peer, char *sni, char *key, char *crt) {
/*
    const char * gnutls_ver = gnutls_check_version(NULL);
    if (!gnutls_ver) { fprintf(stderr, "GnuTLS version mismatch!"); return NULL; }
    fprintf(stderr, "GnuTLS version: <%s>", gnutls_ver);
*/

#ifdef GNUTLS_LOGLEVEL
    gnutls_global_set_log_level(GNUTLS_LOGLEVEL);           // Enable logging (for debugging)
    gnutls_global_set_log_function(gnutls_logger_cb);       // Register logging callback
    gnutls_global_set_audit_log_function(gnutls_audit_cb);  // Enable logging (for auditing)
#endif

    CHECK(gnutls_global_init()); // for backwards compatibility with gnutls < 3.3.0
    CHECK(gnutls_certificate_allocate_credentials(&xcred)); // X509 stuff
    CHECK(gnutls_certificate_set_x509_system_trust(xcred)); // sets the system trusted CAs for Internet PKI

    if (key || crt) { // If client holds a certificate it can be set using the following:
        CHECK(gnutls_certificate_set_x509_key_file (xcred, crt, key, GNUTLS_X509_FMT_PEM) );
    }

    gnutls_session_t session; // Initialize TLS session
    CHECK(gnutls_init(&session, GNUTLS_CLIENT));
    CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, sni, strlen(sni)));
    CHECK(gnutls_set_default_priority(session)); // It is recommended to use the default priorities
    CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred)); // put the x509 credentials to the current session
    gnutls_session_set_verify_cert(session, sni, 0);
    gnutls_transport_set_int(session, peer->fd);

    gnutls_handshake_set_timeout(session, peer->timeout); // GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT

    int ret;
	do {  ret = gnutls_handshake(session); }
	while (ret < 0 && gnutls_error_is_fatal(ret) == 0);
	if (ret < 0) {
		if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
			// check certificate verification status
			int type = gnutls_certificate_type_get(session);
			unsigned status = gnutls_session_get_verify_cert_status(session);
            gnutls_datum_t out;
			CHECK(gnutls_certificate_verification_status_print(status, type, &out, 0));
			vpn_ws_log(" - Cert VERIFY:\n%s\n", out.data);
			gnutls_free(out.data);
		}
		vpn_ws_log(" - Handshake FAILED: %s\n", gnutls_strerror(ret));
        vpn_ws_ssl_close(session, peer->fd);
        return NULL;
	}
	char * desc = gnutls_session_get_desc(session);
	vpn_ws_log(" + Handshaked: %s\n", desc);
	gnutls_free(desc);

	return session;
}


void vpn_ws_ssl_close(gnutls_session_t session, int sd) {
    if (session) {
        gnutls_bye(session, GNUTLS_SHUT_RDWR);
        gnutls_deinit(session);
        if (xcred) gnutls_certificate_free_credentials(xcred);
        gnutls_global_deinit();
    }
    if (sd > 0) close(sd);
}
