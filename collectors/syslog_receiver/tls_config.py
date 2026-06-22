"""tls_config.py — Configuration TLS port 6514"""; import ssl,os
def get_ssl_context():
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.getenv("SYSLOG_CERT_PATH","/certs/syslog-server.crt"),os.getenv("SYSLOG_KEY_PATH","/certs/syslog-server.key"))
    return ctx

