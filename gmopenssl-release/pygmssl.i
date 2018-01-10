%module pygmssl

%{
extern "C"{
#include "openssl/aes.h"
#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/async.h"
#include "openssl/base58.h"
#include "openssl/bb1ibe.h"
#include "openssl/bfibe.h"
#include "openssl/bio.h"
#include "openssl/blowfish.h"
#include "openssl/bn.h"
#include "openssl/bn_gfp2.h"
#include "openssl/bn_hash.h"
#include "openssl/bn_solinas.h"
#include "openssl/buffer.h"
#include "openssl/camellia.h"
#include "openssl/cast.h"
#include "openssl/cmac.h"
#include "openssl/cms.h"
#include "openssl/comp.h"
#include "openssl/conf.h"
#include "openssl/conf_api.h"
#include "openssl/cpk.h"
#include "openssl/crypto.h"
#include "openssl/ct.h"
#include "openssl/des.h"
#include "openssl/dh.h"
#include "openssl/dsa.h"
#include "openssl/dtls1.h"
#include "openssl/e_os2.h"
#include "openssl/ebcdic.h"
#include "openssl/ec.h"
#include "openssl/ec_hash.h"
#include "openssl/ec_type1.h"
#include "openssl/ecdh.h"
#include "openssl/ecdsa.h"
#include "openssl/ecies.h"
#include "openssl/engine.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "openssl/ffx.h"
#include "openssl/fppoint.h"
#include "openssl/gmapi.h"
#include "openssl/gmsaf.h"
#include "openssl/gmsdf.h"
#include "openssl/gmskf.h"
#include "openssl/gmsof.h"
#include "openssl/gmtls.h"
#include "openssl/hkdf.h"
#include "openssl/hmac.h"
#include "openssl/idea.h"
#include "openssl/kdf.h"
#include "openssl/kdf2.h"
#include "openssl/lhash.h"
#include "openssl/md2.h"
#include "openssl/md4.h"
#include "openssl/md5.h"
#include "openssl/mdc2.h"
#include "openssl/modes.h"
#include "openssl/objects.h"
#include "openssl/ocsp.h"
#include "openssl/opensslconf.h"
#include "openssl/opensslv.h"
#include "openssl/ossl_typ.h"
#include "openssl/otp.h"
#include "openssl/paillier.h"
#include "openssl/pem.h"
#include "openssl/pem2.h"
#include "openssl/pem3.h"
#include "openssl/pkcs12.h"
#include "openssl/pkcs7.h"
#include "openssl/rand.h"
#include "openssl/rc2.h"
#include "openssl/rc4.h"
#include "openssl/rc5.h"
#include "openssl/ripemd.h"
#include "openssl/rsa.h"
#include "openssl/saf.h"
#include "openssl/safestack.h"
#include "openssl/sdf.h"
#include "openssl/seed.h"
#include "openssl/serpent.h"
#include "openssl/sgd.h"
#include "openssl/sha.h"
#include "openssl/skf.h"
#include "openssl/sm1.h"
#include "openssl/sm2.h"
#include "openssl/sm3.h"
#include "openssl/sm9.h"
#include "openssl/sms4.h"
#include "openssl/sof.h"
#include "openssl/speck.h"
#include "openssl/srp.h"
#include "openssl/srtp.h"
#include "openssl/ssf33.h"
#include "openssl/ssl.h"
#include "openssl/ssl2.h"
#include "openssl/ssl3.h"
#include "openssl/stack.h"
#include "openssl/symhacks.h"
#include "openssl/tls1.h"
#include "openssl/ts.h"
#include "openssl/txt_db.h"
#include "openssl/ui.h"
#include "openssl/whrlpool.h"
#include "openssl/x509.h"
#include "openssl/x509_vfy.h"
#include "openssl/x509v3.h"
#include "openssl/zuc.h"
#include "openssl/rsa.h"
#include "openssl/sm2.h"
#include "openssl/sm3.h"
#include "openssl/sms4.h"
}
%}

/*----------------------------------------------------  公私钥  ----------------------------------------------------*/
int PEM_get_EVP_CIPHER_INFO(char *header, EVP_CIPHER_INFO *cipher);
int PEM_do_header(EVP_CIPHER_INFO *cipher, unsigned char *data, long *len, pem_password_cb *callback, void *u);
int PEM_read_bio(BIO *bp, char **name, char **header, unsigned char **data, long *len);
int PEM_write_bio(BIO *bp, const char *name, const char *hdr, const unsigned char *data, long len);
int PEM_bytes_read_bio(unsigned char **pdata, long *plen, char **pnm, const char *name, BIO *bp, pem_password_cb *cb, void *u);
void *PEM_ASN1_read_bio(d2i_of_void *d2i, const char *name, BIO *bp, void **x, pem_password_cb *cb, void *u);
int PEM_ASN1_write_bio(i2d_of_void *i2d, const char *name, BIO *bp, void *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
int PEM_X509_INFO_write_bio(BIO *bp, X509_INFO *xi, EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cd, void *u);
int PEM_read(FILE *fp, char **name, char **header, unsigned char **data, long *len);
int PEM_write(FILE *fp, const char *name, const char *hdr, const unsigned char *data, long len);
void *PEM_ASN1_read(d2i_of_void *d2i, const char *name, FILE *fp, void **x, pem_password_cb *cb, void *u);
int PEM_ASN1_write(i2d_of_void *i2d, const char *name, FILE *fp, void *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *callback, void *u);
int PEM_SignInit(EVP_MD_CTX *ctx, EVP_MD *type);
int PEM_SignUpdate(EVP_MD_CTX *ctx, unsigned char *d, unsigned int cnt);
int PEM_SignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, unsigned int *siglen, EVP_PKEY *pkey);
int PEM_def_callback(char *buf, int num, int w, void *key);
void PEM_proc_type(char *buf, int type);
void PEM_dek_info(char *buf, const char *type, int len, char *str);
int PEM_write_bio_PrivateKey_traditional(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);
int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp, EVP_PKEY *x, int nid, char *kstr, int klen, pem_password_cb *cb, void *u);
int PEM_write_bio_PKCS8PrivateKey(BIO *, EVP_PKEY *, const EVP_CIPHER *, char *, int, pem_password_cb *, void *);
int i2d_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_bio(BIO *bp, EVP_PKEY *x, int nid, char *kstr, int klen, pem_password_cb *cb, void *u);
EVP_PKEY *d2i_PKCS8PrivateKey_bio(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cb, void *u);
int i2d_PKCS8PrivateKey_nid_fp(FILE *fp, EVP_PKEY *x, int nid, char *kstr, int klen, pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey_nid(FILE *fp, EVP_PKEY *x, int nid, char *kstr, int klen, pem_password_cb *cb, void *u);
EVP_PKEY *d2i_PKCS8PrivateKey_fp(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc, char *kstr, int klen, pem_password_cb *cd, void *u);
EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);
int PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x);
EVP_PKEY *b2i_PrivateKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PublicKey(const unsigned char **in, long length);
EVP_PKEY *b2i_PrivateKey_bio(BIO *in);
EVP_PKEY *b2i_PublicKey_bio(BIO *in);
int i2b_PrivateKey_bio(BIO *out, EVP_PKEY *pk);
int i2b_PublicKey_bio(BIO *out, EVP_PKEY *pk);
EVP_PKEY *b2i_PVK_bio(BIO *in, pem_password_cb *cb, void *u);
int i2b_PVK_bio(BIO *out, EVP_PKEY *pk, int enclevel, pem_password_cb *cb, void *u);
int ERR_load_PEM_strings(void);

int PKCS7_ISSUER_AND_SERIAL_digest(PKCS7_ISSUER_AND_SERIAL *data, const EVP_MD *type, unsigned char *md, unsigned int *len);
PKCS7 *d2i_PKCS7_fp(FILE *fp, PKCS7 **p7);
int i2d_PKCS7_fp(FILE *fp, PKCS7 *p7);
PKCS7 *PKCS7_dup(PKCS7 *p7);
PKCS7 *d2i_PKCS7_bio(BIO *bp, PKCS7 **p7);
int i2d_PKCS7_bio(BIO *bp, PKCS7 *p7);
int i2d_PKCS7_bio_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);
int PEM_write_bio_PKCS7_stream(BIO *out, PKCS7 *p7, BIO *in, int flags);
long PKCS7_ctrl(PKCS7 *p7, int cmd, long larg, char *parg);
int PKCS7_set_type(PKCS7 *p7, int type);
int PKCS7_set0_type_other(PKCS7 *p7, int type, ASN1_TYPE *other);
int PKCS7_set_content(PKCS7 *p7, PKCS7 *p7_data);
int PKCS7_SIGNER_INFO_set(PKCS7_SIGNER_INFO *p7i, X509 *x509, EVP_PKEY *pkey, const EVP_MD *dgst);
int PKCS7_SIGNER_INFO_sign(PKCS7_SIGNER_INFO *si);
int PKCS7_add_signer(PKCS7 *p7, PKCS7_SIGNER_INFO *p7i);
int PKCS7_add_certificate(PKCS7 *p7, X509 *x509);
int PKCS7_add_crl(PKCS7 *p7, X509_CRL *x509);
int PKCS7_content_new(PKCS7 *p7, int nid);
int PKCS7_dataVerify(X509_STORE *cert_store, X509_STORE_CTX *ctx, BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si);
int PKCS7_signatureVerify(BIO *bio, PKCS7 *p7, PKCS7_SIGNER_INFO *si, X509 *x509);
BIO *PKCS7_dataInit(PKCS7 *p7, BIO *bio);
int PKCS7_dataFinal(PKCS7 *p7, BIO *bio);
BIO *PKCS7_dataDecode(PKCS7 *p7, EVP_PKEY *pkey, BIO *in_bio, X509 *pcert);
PKCS7_SIGNER_INFO *PKCS7_add_signature(PKCS7 *p7, X509 *x509, EVP_PKEY *pkey, const EVP_MD *dgst);
X509 *PKCS7_cert_from_signer_info(PKCS7 *p7, PKCS7_SIGNER_INFO *si);
int PKCS7_set_digest(PKCS7 *p7, const EVP_MD *md);
PKCS7_RECIP_INFO *PKCS7_add_recipient(PKCS7 *p7, X509 *x509);
void PKCS7_SIGNER_INFO_get0_algs(PKCS7_SIGNER_INFO *si, EVP_PKEY **pk, X509_ALGOR **pdig, X509_ALGOR **psig);
void PKCS7_RECIP_INFO_get0_alg(PKCS7_RECIP_INFO *ri, X509_ALGOR **penc);
int PKCS7_add_recipient_info(PKCS7 *p7, PKCS7_RECIP_INFO *ri);
int PKCS7_RECIP_INFO_set(PKCS7_RECIP_INFO *p7i, X509 *x509);
int PKCS7_set_cipher(PKCS7 *p7, const EVP_CIPHER *cipher);
int PKCS7_stream(unsigned char ***boundary, PKCS7 *p7);
PKCS7_ISSUER_AND_SERIAL *PKCS7_get_issuer_and_serial(PKCS7 *p7, int idx);
int PKCS7_add_signed_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int type, void *data);
int PKCS7_add_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int atrtype, void *value);
ASN1_TYPE *PKCS7_get_attribute(PKCS7_SIGNER_INFO *si, int nid);
ASN1_TYPE *PKCS7_get_signed_attribute(PKCS7_SIGNER_INFO *si, int nid);
PKCS7_SIGNER_INFO *PKCS7_sign_add_signer(PKCS7 *p7, X509 *signcert, EVP_PKEY *pkey, const EVP_MD *md, int flags);
int PKCS7_final(PKCS7 *p7, BIO *data, int flags);
int PKCS7_decrypt(PKCS7 *p7, EVP_PKEY *pkey, X509 *cert, BIO *data, int flags);
int PKCS7_add_attrib_content_type(PKCS7_SIGNER_INFO *si, ASN1_OBJECT *coid);
int PKCS7_add0_attrib_signing_time(PKCS7_SIGNER_INFO *si, ASN1_TIME *t);
int PKCS7_add1_attrib_digest(PKCS7_SIGNER_INFO *si, const unsigned char *md, int mdlen);
int SMIME_write_PKCS7(BIO *bio, PKCS7 *p7, BIO *data, int flags);
PKCS7 *SMIME_read_PKCS7(BIO *bio, BIO **bcont);
BIO *BIO_new_PKCS7(BIO *out, PKCS7 *p7);
int ERR_load_PKCS7_strings(void);
ASN1_TYPE *PKCS8_get_attr(PKCS8_PRIV_KEY_INFO *p8, int attr_nid);
int PKCS12_mac_present(const PKCS12 *p12);
void PKCS12_get0_mac(const ASN1_OCTET_STRING **pmac, const X509_ALGOR **pmacalg, const ASN1_OCTET_STRING **psalt, const ASN1_INTEGER **piter, const PKCS12 *p12);
const ASN1_TYPE *PKCS12_SAFEBAG_get0_attr(const PKCS12_SAFEBAG *bag, int attr_nid);
const ASN1_OBJECT *PKCS12_SAFEBAG_get0_type(const PKCS12_SAFEBAG *bag);
int PKCS12_SAFEBAG_get_nid(const PKCS12_SAFEBAG *bag);
int PKCS12_SAFEBAG_get_bag_nid(const PKCS12_SAFEBAG *bag);
X509 *PKCS12_SAFEBAG_get1_cert(const PKCS12_SAFEBAG *bag);
X509_CRL *PKCS12_SAFEBAG_get1_crl(const PKCS12_SAFEBAG *bag);
const PKCS8_PRIV_KEY_INFO *PKCS12_SAFEBAG_get0_p8inf(const PKCS12_SAFEBAG *bag);
const X509_SIG *PKCS12_SAFEBAG_get0_pkcs8(const PKCS12_SAFEBAG *bag);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_cert(X509 *x509);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_crl(X509_CRL *crl);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create0_p8inf(PKCS8_PRIV_KEY_INFO *p8);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create0_pkcs8(X509_SIG *p8);
PKCS12_SAFEBAG *PKCS12_SAFEBAG_create_pkcs8_encrypt(int pbe_nid, const char *pass, int passlen, unsigned char *salt, int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8inf);
PKCS12_SAFEBAG *PKCS12_item_pack_safebag(void *obj, const ASN1_ITEM *it, int nid1, int nid2);
PKCS8_PRIV_KEY_INFO *PKCS8_decrypt(const X509_SIG *p8, const char *pass, int passlen);
PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey(const PKCS12_SAFEBAG *bag, const char *pass, int passlen);
X509_SIG *PKCS8_encrypt(int pbe_nid, const EVP_CIPHER *cipher, const char *pass, int passlen, unsigned char *salt, int saltlen, int iter, PKCS8_PRIV_KEY_INFO *p8);
X509_SIG *PKCS8_set0_pbe(const char *pass, int passlen, PKCS8_PRIV_KEY_INFO *p8inf, X509_ALGOR *pbe);
int PKCS12_add_localkeyid(PKCS12_SAFEBAG *bag, unsigned char *name, int namelen);
int PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag, const char *name, int namelen);
int PKCS12_add_friendlyname_utf8(PKCS12_SAFEBAG *bag, const char *name, int namelen);
int PKCS12_add_CSPName_asc(PKCS12_SAFEBAG *bag, const char *name, int namelen);
int PKCS12_add_friendlyname_uni(PKCS12_SAFEBAG *bag, const unsigned char *name, int namelen);
int PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage);
char *PKCS12_get_friendlyname(PKCS12_SAFEBAG *bag);
unsigned char *PKCS12_pbe_crypt(const X509_ALGOR *algor, const char *pass, int passlen, const unsigned char *in, int inlen, unsigned char **data, int *datalen, int en_de);
void *PKCS12_item_decrypt_d2i(const X509_ALGOR *algor, const ASN1_ITEM *it, const char *pass, int passlen, const ASN1_OCTET_STRING *oct, int zbuf);
ASN1_OCTET_STRING *PKCS12_item_i2d_encrypt(X509_ALGOR *algor, const ASN1_ITEM *it, const char *pass, int passlen, void *obj, int zbuf);
PKCS12 *PKCS12_init(int mode);
int PKCS12_key_gen_asc(const char *pass, int passlen, unsigned char *salt, int saltlen, int id, int iter, int n,unsigned char *out, const EVP_MD *md_type);
int PKCS12_key_gen_uni(unsigned char *pass, int passlen, unsigned char *salt, int saltlen, int id, int iter, int n, unsigned char *out, const EVP_MD *md_type);
int PKCS12_key_gen_utf8(const char *pass, int passlen, unsigned char *salt, int saltlen, int id, int iter, int n, unsigned char *out, const EVP_MD *md_type);
int PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen, ASN1_TYPE *param, const EVP_CIPHER *cipher, const EVP_MD *md_type, int en_de);
int PKCS12_gen_mac(PKCS12 *p12, const char *pass, int passlen, unsigned char *mac, unsigned int *maclen);
int PKCS12_verify_mac(PKCS12 *p12, const char *pass, int passlen);
int PKCS12_set_mac(PKCS12 *p12, const char *pass, int passlen, unsigned char *salt, int saltlen, int iter, const EVP_MD *md_type);
int PKCS12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt, int saltlen, const EVP_MD *md_type);
unsigned char *OPENSSL_asc2uni(const char *asc, int asclen, unsigned char **uni, int *unilen);
char *OPENSSL_uni2asc(const unsigned char *uni, int unilen);
unsigned char *OPENSSL_utf82uni(const char *asc, int asclen, unsigned char **uni, int *unilen);
char *OPENSSL_uni2utf8(const unsigned char *uni, int unilen);
void PKCS12_PBE_add(void);
int i2d_PKCS12_bio(BIO *bp, PKCS12 *p12);
int i2d_PKCS12_fp(FILE *fp, PKCS12 *p12);
PKCS12 *d2i_PKCS12_bio(BIO *bp, PKCS12 **p12);
PKCS12 *d2i_PKCS12_fp(FILE *fp, PKCS12 **p12);
int PKCS12_newpass(PKCS12 *p12, const char *oldpass, const char *newpass);
int ERR_load_PKCS12_strings(void);
void X509_CRL_set_default_method(const X509_CRL_METHOD *meth);
void X509_CRL_METHOD_free(X509_CRL_METHOD *m);
void X509_CRL_set_meth_data(X509_CRL *crl, void *dat);
void *X509_CRL_get_meth_data(X509_CRL *crl);
const char *X509_verify_cert_error_string(long n);
int X509_verify(X509 *a, EVP_PKEY *r);
int X509_REQ_verify(X509_REQ *a, EVP_PKEY *r);
int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r);
int NETSCAPE_SPKI_verify(NETSCAPE_SPKI *a, EVP_PKEY *r);
NETSCAPE_SPKI *NETSCAPE_SPKI_b64_decode(const char *str, int len);
char *NETSCAPE_SPKI_b64_encode(NETSCAPE_SPKI *x);
EVP_PKEY *NETSCAPE_SPKI_get_pubkey(NETSCAPE_SPKI *x);
int NETSCAPE_SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey);
int NETSCAPE_SPKI_print(BIO *out, NETSCAPE_SPKI *spki);
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent);
int X509_signature_print(BIO *bp, const X509_ALGOR *alg, const ASN1_STRING *sig);
int X509_sign(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_sign_ctx(X509 *x, EVP_MD_CTX *ctx);
int X509_http_nbio(OCSP_REQ_CTX *rctx, X509 **pcert);
int X509_REQ_sign(X509_REQ *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_REQ_sign_ctx(X509_REQ *x, EVP_MD_CTX *ctx);
int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_CRL_sign_ctx(X509_CRL *x, EVP_MD_CTX *ctx);
int X509_CRL_http_nbio(OCSP_REQ_CTX *rctx, X509_CRL **pcrl);
int NETSCAPE_SPKI_sign(NETSCAPE_SPKI *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_pubkey_digest(const X509 *data, const EVP_MD *type, unsigned char *md, unsigned int *len);
int X509_digest(const X509 *data, const EVP_MD *type, unsigned char *md, unsigned int *len);
int X509_CRL_digest(const X509_CRL *data, const EVP_MD *type, unsigned char *md, unsigned int *len);
int X509_REQ_digest(const X509_REQ *data, const EVP_MD *type, unsigned char *md, unsigned int *len);
int X509_NAME_digest(const X509_NAME *data, const EVP_MD *type, unsigned char *md, unsigned int *len);
X509 *d2i_X509_fp(FILE *fp, X509 **x509);
int i2d_X509_fp(FILE *fp, X509 *x509);
X509_CRL *d2i_X509_CRL_fp(FILE *fp, X509_CRL **crl);
int i2d_X509_CRL_fp(FILE *fp, X509_CRL *crl);
X509_REQ *d2i_X509_REQ_fp(FILE *fp, X509_REQ **req);
int i2d_X509_REQ_fp(FILE *fp, X509_REQ *req);
RSA *d2i_RSAPrivateKey_fp(FILE *fp, RSA **rsa);
int i2d_RSAPrivateKey_fp(FILE *fp, RSA *rsa);
RSA *d2i_RSAPublicKey_fp(FILE *fp, RSA **rsa);
int i2d_RSAPublicKey_fp(FILE *fp, RSA *rsa);
RSA *d2i_RSA_PUBKEY_fp(FILE *fp, RSA **rsa);
int i2d_RSA_PUBKEY_fp(FILE *fp, RSA *rsa);
DSA *d2i_DSA_PUBKEY_fp(FILE *fp, DSA **dsa);
int i2d_DSA_PUBKEY_fp(FILE *fp, DSA *dsa);
DSA *d2i_DSAPrivateKey_fp(FILE *fp, DSA **dsa);
int i2d_DSAPrivateKey_fp(FILE *fp, DSA *dsa);
EC_KEY *d2i_EC_PUBKEY_fp(FILE *fp, EC_KEY **eckey);
int i2d_EC_PUBKEY_fp(FILE *fp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_fp(FILE *fp, EC_KEY **eckey);
int i2d_ECPrivateKey_fp(FILE *fp, EC_KEY *eckey);
X509_SIG *d2i_PKCS8_fp(FILE *fp, X509_SIG **p8);
int i2d_PKCS8_fp(FILE *fp, X509_SIG *p8);
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_fp(FILE *fp, PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_fp(FILE *fp, EVP_PKEY *key);
int i2d_PrivateKey_fp(FILE *fp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey_fp(FILE *fp, EVP_PKEY **a);
int i2d_PUBKEY_fp(FILE *fp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PUBKEY_fp(FILE *fp, EVP_PKEY **a);
X509 *d2i_X509_bio(BIO *bp, X509 **x509);
int i2d_X509_bio(BIO *bp, X509 *x509);
X509_CRL *d2i_X509_CRL_bio(BIO *bp, X509_CRL **crl);
int i2d_X509_CRL_bio(BIO *bp, X509_CRL *crl);
X509_REQ *d2i_X509_REQ_bio(BIO *bp, X509_REQ **req);
int i2d_X509_REQ_bio(BIO *bp, X509_REQ *req);
RSA *d2i_RSAPrivateKey_bio(BIO *bp, RSA **rsa);
int i2d_RSAPrivateKey_bio(BIO *bp, RSA *rsa);
RSA *d2i_RSAPublicKey_bio(BIO *bp, RSA **rsa);
int i2d_RSAPublicKey_bio(BIO *bp, RSA *rsa);
RSA *d2i_RSA_PUBKEY_bio(BIO *bp, RSA **rsa);
int i2d_RSA_PUBKEY_bio(BIO *bp, RSA *rsa);
DSA *d2i_DSA_PUBKEY_bio(BIO *bp, DSA **dsa);
int i2d_DSA_PUBKEY_bio(BIO *bp, DSA *dsa);
DSA *d2i_DSAPrivateKey_bio(BIO *bp, DSA **dsa);
int i2d_DSAPrivateKey_bio(BIO *bp, DSA *dsa);
EC_KEY *d2i_EC_PUBKEY_bio(BIO *bp, EC_KEY **eckey);
int i2d_EC_PUBKEY_bio(BIO *bp, EC_KEY *eckey);
EC_KEY *d2i_ECPrivateKey_bio(BIO *bp, EC_KEY **eckey);
int i2d_ECPrivateKey_bio(BIO *bp, EC_KEY *eckey);
X509_SIG *d2i_PKCS8_bio(BIO *bp, X509_SIG **p8);
int i2d_PKCS8_bio(BIO *bp, X509_SIG *p8);
PKCS8_PRIV_KEY_INFO *d2i_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, PKCS8_PRIV_KEY_INFO **p8inf);
int i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bp, PKCS8_PRIV_KEY_INFO *p8inf);
int i2d_PKCS8PrivateKeyInfo_bio(BIO *bp, EVP_PKEY *key);
int i2d_PrivateKey_bio(BIO *bp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PrivateKey_bio(BIO *bp, EVP_PKEY **a);
int i2d_PUBKEY_bio(BIO *bp, EVP_PKEY *pkey);
EVP_PKEY *d2i_PUBKEY_bio(BIO *bp, EVP_PKEY **a);
X509 *X509_dup(X509 *x509);
X509_ATTRIBUTE *X509_ATTRIBUTE_dup(X509_ATTRIBUTE *xa);
X509_EXTENSION *X509_EXTENSION_dup(X509_EXTENSION *ex);
X509_CRL *X509_CRL_dup(X509_CRL *crl);
X509_REVOKED *X509_REVOKED_dup(X509_REVOKED *rev);
X509_REQ *X509_REQ_dup(X509_REQ *req);
X509_ALGOR *X509_ALGOR_dup(X509_ALGOR *xn);
int X509_ALGOR_set0(X509_ALGOR *alg, ASN1_OBJECT *aobj, int ptype, void *pval);
void X509_ALGOR_get0(const ASN1_OBJECT **paobj, int *pptype, const void **ppval, const X509_ALGOR *algor);
void X509_ALGOR_set_md(X509_ALGOR *alg, const EVP_MD *md);
int X509_ALGOR_cmp(const X509_ALGOR *a, const X509_ALGOR *b);
X509_NAME *X509_NAME_dup(X509_NAME *xn);
X509_NAME_ENTRY *X509_NAME_ENTRY_dup(X509_NAME_ENTRY *ne);
int X509_cmp_time(const ASN1_TIME *s, time_t *t);
int X509_cmp_current_time(const ASN1_TIME *s);
ASN1_TIME *X509_time_adj(ASN1_TIME *s, long adj, time_t *t);
ASN1_TIME *X509_time_adj_ex(ASN1_TIME *s, int offset_day, long offset_sec, time_t *t);
ASN1_TIME *X509_gmtime_adj(ASN1_TIME *s, long adj);
const char *X509_get_default_cert_area(void);
const char *X509_get_default_cert_dir(void);
const char *X509_get_default_cert_file(void);
const char *X509_get_default_cert_dir_env(void);
const char *X509_get_default_cert_file_env(void);
const char *X509_get_default_private_dir(void);
X509_REQ *X509_to_X509_REQ(X509 *x, EVP_PKEY *pkey, const EVP_MD *md);
X509 *X509_REQ_to_X509(X509_REQ *r, int days, EVP_PKEY *pkey);
int X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey);
EVP_PKEY *X509_PUBKEY_get0(X509_PUBKEY *key);
EVP_PKEY *X509_PUBKEY_get(X509_PUBKEY *key);
long X509_get_pathlen(X509 *x);
int i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp);
EVP_PKEY *d2i_PUBKEY(EVP_PKEY **a, const unsigned char **pp, long length);
int i2d_RSA_PUBKEY(RSA *a, unsigned char **pp);
RSA *d2i_RSA_PUBKEY(RSA **a, const unsigned char **pp, long length);
int i2d_DSA_PUBKEY(DSA *a, unsigned char **pp);
DSA *d2i_DSA_PUBKEY(DSA **a, const unsigned char **pp, long length);
int i2d_EC_PUBKEY(EC_KEY *a, unsigned char **pp);
EC_KEY *d2i_EC_PUBKEY(EC_KEY **a, const unsigned char **pp, long length);
int i2d_PAILLIER_PUBKEY(PAILLIER *a, unsigned char **pp);
PAILLIER *d2i_PAILLIER_PUBKEY(PAILLIER **a, const unsigned char **pp, long length);
void X509_SIG_get0(const X509_SIG *sig, const X509_ALGOR **palg, const ASN1_OCTET_STRING **pdigest);
void X509_SIG_getm(X509_SIG *sig, X509_ALGOR **palg, ASN1_OCTET_STRING **pdigest);
X509_ATTRIBUTE *X509_ATTRIBUTE_create(int nid, int atrtype, void *value);
int X509_NAME_set(X509_NAME **xn, X509_NAME *name);
int X509_set_ex_data(X509 *r, int idx, void *arg);
void *X509_get_ex_data(X509 *r, int idx);
int i2d_X509_AUX(X509 *a, unsigned char **pp);
X509 *d2i_X509_AUX(X509 **a, const unsigned char **pp, long length);
int i2d_re_X509_tbs(X509 *x, unsigned char **pp);
void X509_get0_signature(const ASN1_BIT_STRING **psig, const X509_ALGOR **palg, const X509 *x);
int X509_get_signature_nid(const X509 *x);
int X509_trusted(const X509 *x);
int X509_alias_set1(X509 *x, const unsigned char *name, int len);
int X509_keyid_set1(X509 *x, const unsigned char *id, int len);
unsigned char *X509_alias_get0(X509 *x, int *len);
unsigned char *X509_keyid_get0(X509 *x, int *len);
int (*X509_TRUST_set_default(int (*trust) (int, X509 *, int))) (int, X509 *, int);
int X509_TRUST_set(int *t, int trust);
int X509_add1_trust_object(X509 *x, const ASN1_OBJECT *obj);
int X509_add1_reject_object(X509 *x, const ASN1_OBJECT *obj);
void X509_trust_clear(X509 *x);
void X509_reject_clear(X509 *x);
int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
int X509_CRL_get0_by_serial(X509_CRL *crl, X509_REVOKED **ret, ASN1_INTEGER *serial);
int X509_CRL_get0_by_cert(X509_CRL *crl, X509_REVOKED **ret, X509 *x);
X509_PKEY *X509_PKEY_new(void);
void X509_PKEY_free(X509_PKEY *a);
X509_INFO *X509_INFO_new(void);
void X509_INFO_free(X509_INFO *a);
char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size);
int ASN1_verify(i2d_of_void *i2d, X509_ALGOR *algor1, ASN1_BIT_STRING *signature, char *data, EVP_PKEY *pkey);
int ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data, unsigned char *md, unsigned int *len);
int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1, X509_ALGOR *algor2, ASN1_BIT_STRING *signature, char *data, EVP_PKEY *pkey, const EVP_MD *type);
int ASN1_item_digest(const ASN1_ITEM *it, const EVP_MD *type, void *data, unsigned char *md, unsigned int *len);
int ASN1_item_verify(const ASN1_ITEM *it, X509_ALGOR *algor1, ASN1_BIT_STRING *signature, void *data, EVP_PKEY *pkey);
int ASN1_item_sign(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2, ASN1_BIT_STRING *signature, void *data, EVP_PKEY *pkey, const EVP_MD *type);
int ASN1_item_sign_ctx(const ASN1_ITEM *it, X509_ALGOR *algor1, X509_ALGOR *algor2, ASN1_BIT_STRING *signature, void *asn, EVP_MD_CTX *ctx);
long X509_get_version(const X509 *x);
int X509_set_version(X509 *x, long version);
int X509_set_serialNumber(X509 *x, ASN1_INTEGER *serial);
ASN1_INTEGER *X509_get_serialNumber(X509 *x);
const ASN1_INTEGER *X509_get0_serialNumber(const X509 *x);
int X509_set_issuer_name(X509 *x, X509_NAME *name);
X509_NAME *X509_get_issuer_name(const X509 *a);
int X509_set_subject_name(X509 *x, X509_NAME *name);
X509_NAME *X509_get_subject_name(const X509 *a);
const ASN1_TIME * X509_get0_notBefore(const X509 *x);
ASN1_TIME *X509_getm_notBefore(const X509 *x);
int X509_set1_notBefore(X509 *x, const ASN1_TIME *tm);
const ASN1_TIME *X509_get0_notAfter(const X509 *x);
ASN1_TIME *X509_getm_notAfter(const X509 *x);
int X509_set1_notAfter(X509 *x, const ASN1_TIME *tm);
int X509_set_pubkey(X509 *x, EVP_PKEY *pkey);
int X509_up_ref(X509 *x);
int X509_get_signature_type(const X509 *x);
X509_PUBKEY *X509_get_X509_PUBKEY(const X509 *x);
void X509_get0_uids(const X509 *x, const ASN1_BIT_STRING **piuid, const ASN1_BIT_STRING **psuid);
const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x);
EVP_PKEY *X509_get0_pubkey(const X509 *x);
EVP_PKEY *X509_get_pubkey(X509 *x);
ASN1_BIT_STRING *X509_get0_pubkey_bitstr(const X509 *x);
int X509_certificate_type(const X509 *x, const EVP_PKEY *pubkey);
long X509_REQ_get_version(const X509_REQ *req);
int X509_REQ_set_version(X509_REQ *x, long version);
X509_NAME *X509_REQ_get_subject_name(const X509_REQ *req);
int X509_REQ_set_subject_name(X509_REQ *req, X509_NAME *name);
void X509_REQ_get0_signature(const X509_REQ *req, const ASN1_BIT_STRING **psig, const X509_ALGOR **palg);
int X509_REQ_get_signature_nid(const X509_REQ *req);
int i2d_re_X509_REQ_tbs(X509_REQ *req, unsigned char **pp);
int X509_REQ_set_pubkey(X509_REQ *x, EVP_PKEY *pkey);
EVP_PKEY *X509_REQ_get_pubkey(X509_REQ *req);
EVP_PKEY *X509_REQ_get0_pubkey(X509_REQ *req);
X509_PUBKEY *X509_REQ_get_X509_PUBKEY(X509_REQ *req);
int X509_REQ_extension_nid(int nid);
int *X509_REQ_get_extension_nids(void);
void X509_REQ_set_extension_nids(int *nids);
int X509_REQ_get_attr_count(const X509_REQ *req);
int X509_REQ_get_attr_by_NID(const X509_REQ *req, int nid, int lastpos);
int X509_REQ_get_attr_by_OBJ(const X509_REQ *req, const ASN1_OBJECT *obj, int lastpos);
X509_ATTRIBUTE *X509_REQ_get_attr(const X509_REQ *req, int loc);
X509_ATTRIBUTE *X509_REQ_delete_attr(X509_REQ *req, int loc);
int X509_REQ_add1_attr(X509_REQ *req, X509_ATTRIBUTE *attr);
int X509_REQ_add1_attr_by_OBJ(X509_REQ *req, const ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len);
int X509_REQ_add1_attr_by_NID(X509_REQ *req, int nid, int type, const unsigned char *bytes, int len);
int X509_REQ_add1_attr_by_txt(X509_REQ *req, const char *attrname, int type, const unsigned char *bytes, int len);
int X509_CRL_set_version(X509_CRL *x, long version);
int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
int X509_CRL_set1_lastUpdate(X509_CRL *x, const ASN1_TIME *tm);
int X509_CRL_set1_nextUpdate(X509_CRL *x, const ASN1_TIME *tm);
int X509_CRL_sort(X509_CRL *crl);
int X509_CRL_up_ref(X509_CRL *crl);
long X509_CRL_get_version(const X509_CRL *crl);
const ASN1_TIME *X509_CRL_get0_lastUpdate(const X509_CRL *crl);
const ASN1_TIME *X509_CRL_get0_nextUpdate(const X509_CRL *crl);
X509_NAME *X509_CRL_get_issuer(const X509_CRL *crl);
void X509_CRL_get0_signature(const X509_CRL *crl, const ASN1_BIT_STRING **psig, const X509_ALGOR **palg);
int X509_CRL_get_signature_nid(const X509_CRL *crl);
int i2d_re_X509_CRL_tbs(X509_CRL *req, unsigned char **pp);
const ASN1_INTEGER *X509_REVOKED_get0_serialNumber(const X509_REVOKED *x);
int X509_REVOKED_set_serialNumber(X509_REVOKED *x, ASN1_INTEGER *serial);
const ASN1_TIME *X509_REVOKED_get0_revocationDate(const X509_REVOKED *x);
int X509_REVOKED_set_revocationDate(X509_REVOKED *r, ASN1_TIME *tm);
X509_CRL *X509_CRL_diff(X509_CRL *base, X509_CRL *newer, EVP_PKEY *skey, const EVP_MD *md, unsigned int flags);
int X509_REQ_check_private_key(X509_REQ *x509, EVP_PKEY *pkey);
int X509_check_private_key(const X509 *x509, const EVP_PKEY *pkey);
int X509_CRL_check_suiteb(X509_CRL *crl, EVP_PKEY *pk, unsigned long flags);
int X509_issuer_and_serial_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_and_serial_hash(X509 *a);
int X509_issuer_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_issuer_name_hash(X509 *a);
int X509_subject_name_cmp(const X509 *a, const X509 *b);
unsigned long X509_subject_name_hash(X509 *x);
unsigned long X509_issuer_name_hash_old(X509 *a);
unsigned long X509_subject_name_hash_old(X509 *x);
int X509_cmp(const X509 *a, const X509 *b);
int X509_NAME_cmp(const X509_NAME *a, const X509_NAME *b);
unsigned long X509_NAME_hash(X509_NAME *x);
unsigned long X509_NAME_hash_old(X509_NAME *x);
int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b);
int X509_CRL_match(const X509_CRL *a, const X509_CRL *b);
int X509_aux_print(BIO *out, X509 *x, int indent);
int X509_print_ex_fp(FILE *bp, X509 *x, unsigned long nmflag, unsigned long cflag);
int X509_print_fp(FILE *bp, X509 *x);
int X509_CRL_print_fp(FILE *bp, X509_CRL *x);
int X509_REQ_print_fp(FILE *bp, X509_REQ *req);
int X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, int indent, unsigned long flags);
int X509_NAME_print(BIO *bp, const X509_NAME *name, int obase);
int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent, unsigned long flags);
int X509_print_ex(BIO *bp, X509 *x, unsigned long nmflag, unsigned long cflag);
int X509_print(BIO *bp, X509 *x);
int X509_ocspid_print(BIO *bp, X509 *x);
int X509_CRL_print(BIO *bp, X509_CRL *x);
int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag, unsigned long cflag);
int X509_REQ_print(BIO *bp, X509_REQ *req);
int X509_NAME_entry_count(const X509_NAME *name);
int X509_NAME_get_text_by_NID(X509_NAME *name, int nid, char *buf, int len);
int X509_NAME_get_text_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, char *buf, int len);
int X509_NAME_get_index_by_NID(X509_NAME *name, int nid, int lastpos);
int X509_NAME_get_index_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int lastpos);
X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *name, int loc);
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *name, int loc);
int X509_NAME_add_entry(X509_NAME *name, const X509_NAME_ENTRY *ne, int loc, int set);
int X509_NAME_add_entry_by_OBJ(X509_NAME *name, const ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len, int loc, int set);
int X509_NAME_add_entry_by_NID(X509_NAME *name, int nid, int type, const unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_txt(X509_NAME_ENTRY **ne, const char *field, int type, const unsigned char *bytes, int len);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_NID(X509_NAME_ENTRY **ne, int nid, int type, const unsigned char *bytes, int len);
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field, int type, const unsigned char *bytes, int len, int loc, int set);
X509_NAME_ENTRY *X509_NAME_ENTRY_create_by_OBJ(X509_NAME_ENTRY **ne, const ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len);
int X509_NAME_ENTRY_set_object(X509_NAME_ENTRY *ne, const ASN1_OBJECT *obj);
int X509_NAME_ENTRY_set_data(X509_NAME_ENTRY *ne, int type, const unsigned char *bytes, int len);
ASN1_OBJECT *X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY *ne);
ASN1_STRING * X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne);
int X509_NAME_ENTRY_set(const X509_NAME_ENTRY *ne);
int X509_NAME_get0_der(X509_NAME *nm, const unsigned char **pder, size_t *pderlen);
int X509_get_ext_count(const X509 *x);
int X509_get_ext_by_NID(const X509 *x, int nid, int lastpos);
int X509_get_ext_by_OBJ(const X509 *x, const ASN1_OBJECT *obj, int lastpos);
int X509_get_ext_by_critical(const X509 *x, int crit, int lastpos);
X509_EXTENSION *X509_get_ext(const X509 *x, int loc);
X509_EXTENSION *X509_delete_ext(X509 *x, int loc);
int X509_add_ext(X509 *x, X509_EXTENSION *ex, int loc);
void *X509_get_ext_d2i(const X509 *x, int nid, int *crit, int *idx);
int X509_add1_ext_i2d(X509 *x, int nid, void *value, int crit, unsigned long flags);
int X509_CRL_get_ext_count(const X509_CRL *x);
int X509_CRL_get_ext_by_NID(const X509_CRL *x, int nid, int lastpos);
int X509_CRL_get_ext_by_OBJ(const X509_CRL *x, const ASN1_OBJECT *obj, int lastpos);
int X509_CRL_get_ext_by_critical(const X509_CRL *x, int crit, int lastpos);
X509_EXTENSION *X509_CRL_get_ext(const X509_CRL *x, int loc);
X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc);
int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc);
void *X509_CRL_get_ext_d2i(const X509_CRL *x, int nid, int *crit, int *idx);
int X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit, unsigned long flags);
int X509_REVOKED_get_ext_count(const X509_REVOKED *x);
int X509_REVOKED_get_ext_by_NID(const X509_REVOKED *x, int nid, int lastpos);
int X509_REVOKED_get_ext_by_OBJ(const X509_REVOKED *x, const ASN1_OBJECT *obj, int lastpos);
int X509_REVOKED_get_ext_by_critical(const X509_REVOKED *x, int crit, int lastpos);
X509_EXTENSION *X509_REVOKED_get_ext(const X509_REVOKED *x, int loc);
X509_EXTENSION *X509_REVOKED_delete_ext(X509_REVOKED *x, int loc);
int X509_REVOKED_add_ext(X509_REVOKED *x, X509_EXTENSION *ex, int loc);
void *X509_REVOKED_get_ext_d2i(const X509_REVOKED *x, int nid, int *crit, int *idx);
int X509_REVOKED_add1_ext_i2d(X509_REVOKED *x, int nid, void *value, int crit, unsigned long flags);
X509_EXTENSION *X509_EXTENSION_create_by_NID(X509_EXTENSION **ex, int nid, int crit, ASN1_OCTET_STRING *data);
X509_EXTENSION *X509_EXTENSION_create_by_OBJ(X509_EXTENSION **ex, const ASN1_OBJECT *obj, int crit,ASN1_OCTET_STRING *data);
int X509_EXTENSION_set_object(X509_EXTENSION *ex, const ASN1_OBJECT *obj);
int X509_EXTENSION_set_critical(X509_EXTENSION *ex, int crit);
int X509_EXTENSION_set_data(X509_EXTENSION *ex, ASN1_OCTET_STRING *data);
ASN1_OBJECT *X509_EXTENSION_get_object(X509_EXTENSION *ex);
ASN1_OCTET_STRING *X509_EXTENSION_get_data(X509_EXTENSION *ne);
int X509_EXTENSION_get_critical(const X509_EXTENSION *ex);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_NID(X509_ATTRIBUTE **attr, int nid, int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_OBJ(X509_ATTRIBUTE **attr, const ASN1_OBJECT *obj, int atrtype, const void *data, int len);
X509_ATTRIBUTE *X509_ATTRIBUTE_create_by_txt(X509_ATTRIBUTE **attr, const char *atrname, int type, const unsigned char *bytes, int len);
int X509_ATTRIBUTE_set1_object(X509_ATTRIBUTE *attr, const ASN1_OBJECT *obj);
int X509_ATTRIBUTE_set1_data(X509_ATTRIBUTE *attr, int attrtype, const void *data, int len);
void *X509_ATTRIBUTE_get0_data(X509_ATTRIBUTE *attr, int idx, int atrtype, void *data);
int X509_ATTRIBUTE_count(const X509_ATTRIBUTE *attr);
ASN1_OBJECT *X509_ATTRIBUTE_get0_object(X509_ATTRIBUTE *attr);
ASN1_TYPE *X509_ATTRIBUTE_get0_type(X509_ATTRIBUTE *attr, int idx);
int EVP_PKEY_get_attr_count(const EVP_PKEY *key);
int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid, int lastpos);
int EVP_PKEY_get_attr_by_OBJ(const EVP_PKEY *key, const ASN1_OBJECT *obj, int lastpos);
X509_ATTRIBUTE *EVP_PKEY_get_attr(const EVP_PKEY *key, int loc);
X509_ATTRIBUTE *EVP_PKEY_delete_attr(EVP_PKEY *key, int loc);
int EVP_PKEY_add1_attr(EVP_PKEY *key, X509_ATTRIBUTE *attr);
int EVP_PKEY_add1_attr_by_OBJ(EVP_PKEY *key, const ASN1_OBJECT *obj, int type, const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_NID(EVP_PKEY *key, int nid, int type, const unsigned char *bytes, int len);
int EVP_PKEY_add1_attr_by_txt(EVP_PKEY *key, const char *attrname, int type, const unsigned char *bytes, int len);
int X509_verify_cert(X509_STORE_CTX *ctx);
int PKCS5_pbe_set0_algor(X509_ALGOR *algor, int alg, int iter, const unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe_set(int alg, int iter, const unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe2_set(const EVP_CIPHER *cipher, int iter, unsigned char *salt, int saltlen);
X509_ALGOR *PKCS5_pbe2_set_iv(const EVP_CIPHER *cipher, int iter, unsigned char *salt, int saltlen, unsigned char *aiv, int prf_nid);
X509_ALGOR *PKCS5_pbe2_set_scrypt(const EVP_CIPHER *cipher, const unsigned char *salt, int saltlen, unsigned char *aiv, uint64_t N, uint64_t r, uint64_t p);
X509_ALGOR *PKCS5_pbkdf2_set(int iter, unsigned char *salt, int saltlen, int prf_nid, int keylen);
EVP_PKEY *EVP_PKCS82PKEY(const PKCS8_PRIV_KEY_INFO *p8);
PKCS8_PRIV_KEY_INFO *EVP_PKEY2PKCS8(EVP_PKEY *pkey);
int PKCS8_pkey_set0(PKCS8_PRIV_KEY_INFO *priv, ASN1_OBJECT *aobj, int version, int ptype, void *pval, unsigned char *penc, int penclen);
int PKCS8_pkey_get0(const ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen, const X509_ALGOR **pa, const PKCS8_PRIV_KEY_INFO *p8);
int PKCS8_pkey_add1_attr_by_NID(PKCS8_PRIV_KEY_INFO *p8, int nid, int type, const unsigned char *bytes, int len);
int X509_PUBKEY_set0_param(X509_PUBKEY *pub, ASN1_OBJECT *aobj, int ptype, void *pval, unsigned char *penc, int penclen);
int X509_PUBKEY_get0_param(ASN1_OBJECT **ppkalg, const unsigned char **pk, int *ppklen, X509_ALGOR **pa, X509_PUBKEY *pub);
int X509_check_trust(X509 *x, int id, int flags);
int X509_TRUST_get_count(void);
X509_TRUST *X509_TRUST_get0(int idx);
int X509_TRUST_get_by_id(int id);
void X509_TRUST_cleanup(void);
int X509_TRUST_get_flags(const X509_TRUST *xp);
char *X509_TRUST_get0_name(const X509_TRUST *xp);
int X509_TRUST_get_trust(const X509_TRUST *xp);
int ERR_load_X509_strings(void);
int X509_OBJECT_up_ref_count(X509_OBJECT *a);
X509_OBJECT *X509_OBJECT_new(void);
void X509_OBJECT_free(X509_OBJECT *a);
X509_LOOKUP_TYPE X509_OBJECT_get_type(const X509_OBJECT *a);
X509 *X509_OBJECT_get0_X509(const X509_OBJECT *a);
X509_CRL *X509_OBJECT_get0_X509_CRL(X509_OBJECT *a);
X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *v);
int X509_STORE_lock(X509_STORE *ctx);
int X509_STORE_unlock(X509_STORE *ctx);
int X509_STORE_up_ref(X509_STORE *v);
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);
int X509_STORE_set_purpose(X509_STORE *ctx, int purpose);
int X509_STORE_set_trust(X509_STORE *ctx, int trust);
int X509_STORE_set1_param(X509_STORE *ctx, X509_VERIFY_PARAM *pm);
X509_VERIFY_PARAM *X509_STORE_get0_param(X509_STORE *ctx);
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);
void X509_STORE_set_verify(X509_STORE *ctx, X509_STORE_CTX_verify_fn verify);
void X509_STORE_CTX_set_verify(X509_STORE_CTX *ctx, X509_STORE_CTX_verify_fn verify);
X509_STORE_CTX_verify_fn X509_STORE_get_verify(X509_STORE *ctx);
void X509_STORE_set_verify_cb(X509_STORE *ctx, X509_STORE_CTX_verify_cb verify_cb);
X509_STORE_CTX_verify_cb X509_STORE_get_verify_cb(X509_STORE *ctx);
void X509_STORE_set_get_issuer(X509_STORE *ctx, X509_STORE_CTX_get_issuer_fn get_issuer);
X509_STORE_CTX_get_issuer_fn X509_STORE_get_get_issuer(X509_STORE *ctx);
void X509_STORE_set_check_issued(X509_STORE *ctx, X509_STORE_CTX_check_issued_fn check_issued);
X509_STORE_CTX_check_issued_fn X509_STORE_get_check_issued(X509_STORE *ctx);
void X509_STORE_set_check_revocation(X509_STORE *ctx, X509_STORE_CTX_check_revocation_fn check_revocation);
X509_STORE_CTX_check_revocation_fn X509_STORE_get_check_revocation(X509_STORE *ctx);
void X509_STORE_set_get_crl(X509_STORE *ctx, X509_STORE_CTX_get_crl_fn get_crl);
X509_STORE_CTX_get_crl_fn X509_STORE_get_get_crl(X509_STORE *ctx);
void X509_STORE_set_check_crl(X509_STORE *ctx, X509_STORE_CTX_check_crl_fn check_crl);
X509_STORE_CTX_check_crl_fn X509_STORE_get_check_crl(X509_STORE *ctx);
void X509_STORE_set_cert_crl(X509_STORE *ctx, X509_STORE_CTX_cert_crl_fn cert_crl);
X509_STORE_CTX_cert_crl_fn X509_STORE_get_cert_crl(X509_STORE *ctx);
void X509_STORE_set_check_policy(X509_STORE *ctx, X509_STORE_CTX_check_policy_fn check_policy);
X509_STORE_CTX_check_policy_fn X509_STORE_get_check_policy(X509_STORE *ctx);
void X509_STORE_set_lookup_certs(X509_STORE *ctx, X509_STORE_CTX_lookup_certs_fn lookup_certs);
X509_STORE_CTX_lookup_certs_fn X509_STORE_get_lookup_certs(X509_STORE *ctx);
void X509_STORE_set_lookup_crls(X509_STORE *ctx, X509_STORE_CTX_lookup_crls_fn lookup_crls);
X509_STORE_CTX_lookup_crls_fn X509_STORE_get_lookup_crls(X509_STORE *ctx);
void X509_STORE_set_cleanup(X509_STORE *ctx, X509_STORE_CTX_cleanup_fn cleanup);
X509_STORE_CTX_cleanup_fn X509_STORE_get_cleanup(X509_STORE *ctx);
int X509_STORE_set_ex_data(X509_STORE *ctx, int idx, void *data);
void *X509_STORE_get_ex_data(X509_STORE *ctx, int idx);
X509_STORE_CTX *X509_STORE_CTX_new(void);
int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
X509_STORE *X509_STORE_CTX_get0_store(X509_STORE_CTX *ctx);
X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx, X509_STORE_CTX_verify_cb verify);
X509_STORE_CTX_verify_cb X509_STORE_CTX_get_verify_cb(X509_STORE_CTX *ctx);
X509_STORE_CTX_verify_fn X509_STORE_CTX_get_verify(X509_STORE_CTX *ctx);
X509_STORE_CTX_get_issuer_fn X509_STORE_CTX_get_get_issuer(X509_STORE_CTX *ctx);
X509_STORE_CTX_check_issued_fn X509_STORE_CTX_get_check_issued(X509_STORE_CTX *ctx);
X509_STORE_CTX_check_revocation_fn X509_STORE_CTX_get_check_revocation(X509_STORE_CTX *ctx);
X509_STORE_CTX_get_crl_fn X509_STORE_CTX_get_get_crl(X509_STORE_CTX *ctx);
X509_STORE_CTX_check_crl_fn X509_STORE_CTX_get_check_crl(X509_STORE_CTX *ctx);
X509_STORE_CTX_cert_crl_fn X509_STORE_CTX_get_cert_crl(X509_STORE_CTX *ctx);
X509_STORE_CTX_check_policy_fn X509_STORE_CTX_get_check_policy(X509_STORE_CTX *ctx);
X509_STORE_CTX_lookup_certs_fn X509_STORE_CTX_get_lookup_certs(X509_STORE_CTX *ctx);
X509_STORE_CTX_lookup_crls_fn X509_STORE_CTX_get_lookup_crls(X509_STORE_CTX *ctx);
X509_STORE_CTX_cleanup_fn X509_STORE_CTX_get_cleanup(X509_STORE_CTX *ctx);
X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *v, X509_LOOKUP_METHOD *m);
X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void);
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);
int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x);
int X509_STORE_CTX_get_by_subject(X509_STORE_CTX *vs, X509_LOOKUP_TYPE type, X509_NAME *name, X509_OBJECT *ret);
X509_OBJECT *X509_STORE_CTX_get_obj_by_subject(X509_STORE_CTX *vs, X509_LOOKUP_TYPE type, X509_NAME *name);
int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret);
int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type);
X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method);
void X509_LOOKUP_free(X509_LOOKUP *ctx);
int X509_LOOKUP_init(X509_LOOKUP *ctx);
int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, X509_NAME *name, X509_OBJECT *ret);
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, X509_NAME *name, ASN1_INTEGER *serial, X509_OBJECT *ret);
int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const unsigned char *bytes, int len, X509_OBJECT *ret);
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type, const char *str, int len, X509_OBJECT *ret);
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);
int X509_STORE_load_locations(X509_STORE *ctx, const char *file, const char *dir);
int X509_STORE_set_default_paths(X509_STORE *ctx);
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data);
void *X509_STORE_CTX_get_ex_data(X509_STORE_CTX *ctx, int idx);
int X509_STORE_CTX_get_error(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int s);
int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error_depth(X509_STORE_CTX *ctx, int depth);
X509 *X509_STORE_CTX_get_current_cert(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_current_cert(X509_STORE_CTX *ctx, X509 *x);
X509 *X509_STORE_CTX_get0_current_issuer(X509_STORE_CTX *ctx);
X509_CRL *X509_STORE_CTX_get0_current_crl(X509_STORE_CTX *ctx);
X509_STORE_CTX *X509_STORE_CTX_get0_parent_ctx(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_cert(X509_STORE_CTX *c, X509 *x);
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust);
int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose, int purpose, int trust);
void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags);
void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags, time_t t);
X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_explicit_policy(X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_num_untrusted(X509_STORE_CTX *ctx);
X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);
void X509_STORE_CTX_set0_dane(X509_STORE_CTX *ctx, SSL_DANE *dane);
X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *to, const X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to, const X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param, unsigned long flags);
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param, unsigned long flags);
unsigned long X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose);
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust);
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth);
void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM *param, int auth_level);
time_t X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM *param);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);
int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param, ASN1_OBJECT *policy);
int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM *param, uint32_t flags);
uint32_t X509_VERIFY_PARAM_get_inh_flags(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param, const char *name, size_t namelen);
int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param, const char *name, size_t namelen);
void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param, unsigned int flags);
char *X509_VERIFY_PARAM_get0_peername(X509_VERIFY_PARAM *);
void X509_VERIFY_PARAM_move_peername(X509_VERIFY_PARAM *, X509_VERIFY_PARAM *);
int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *param, const char *email, size_t emaillen);
int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param, const unsigned char *ip, size_t iplen);
int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM *param, const char *ipasc);
int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_get_auth_level(const X509_VERIFY_PARAM *param);
const char *X509_VERIFY_PARAM_get0_name(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_get_count(void);
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_get0(int id);
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name);
void X509_VERIFY_PARAM_table_cleanup(void);
void X509_policy_tree_free(X509_POLICY_TREE *tree);
int X509_policy_tree_level_count(const X509_POLICY_TREE *tree);
X509_POLICY_LEVEL *X509_policy_tree_get0_level(const X509_POLICY_TREE *tree, int i);
int X509_policy_level_node_count(X509_POLICY_LEVEL *level);
X509_POLICY_NODE *X509_policy_level_get0_node(X509_POLICY_LEVEL *level, int i);
const ASN1_OBJECT *X509_policy_node_get0_policy(const X509_POLICY_NODE *node);
const X509_POLICY_NODE *X509_policy_node_get0_parent(const X509_POLICY_NODE *node);
int SXNET_add_id_asc(SXNET **psx, const char *zone, const char *user, int userlen);
int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, const char *user, int userlen);
int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *izone, const char *user, int userlen);
ASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, const char *zone);
ASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone);
ASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, ASN1_INTEGER *zone);
GENERAL_NAME *GENERAL_NAME_dup(GENERAL_NAME *a);
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b);
char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method, ASN1_IA5STRING *ia5);
ASN1_IA5STRING *s2i_ASN1_IA5STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *str);
int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen);
int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b);
void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value);
void *GENERAL_NAME_get0_value(GENERAL_NAME *a, int *ptype);
int GENERAL_NAME_set0_othername(GENERAL_NAME *gen, ASN1_OBJECT *oid, ASN1_TYPE *value);
int GENERAL_NAME_get0_otherName(GENERAL_NAME *gen, ASN1_OBJECT **poid, ASN1_TYPE **pvalue);
char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, const ASN1_OCTET_STRING *ia5);
ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, const char *str);
int i2a_ACCESS_DESCRIPTION(BIO *bp, const ACCESS_DESCRIPTION *a);
int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, X509_NAME *iname);
int NAME_CONSTRAINTS_check(X509 *x, NAME_CONSTRAINTS *nc);
int NAME_CONSTRAINTS_check_CN(X509 *x, NAME_CONSTRAINTS *nc);
GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out, const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, int gen_type, const char *value, int is_nc);
GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, CONF_VALUE *cnf);
GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out, const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, CONF_VALUE *cnf, int is_nc);
void X509V3_conf_free(CONF_VALUE *val);
X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid, const char *value);
X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, const char *name, const char *value);
int X509V3_EXT_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section, X509 *cert);
int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section, X509_REQ *req);
int X509V3_EXT_CRL_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section, X509_CRL *crl);
int X509V3_get_value_bool(const CONF_VALUE *value, int *asn1_bool);
int X509V3_get_value_int(const CONF_VALUE *value, ASN1_INTEGER **aint);
void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf);
char *X509V3_get_string(X509V3_CTX *ctx, const char *name, const char *section);
void X509V3_string_free(X509V3_CTX *ctx, char *str);
void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject, X509_REQ *req, X509_CRL *crl, int flags);
char *i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const ASN1_INTEGER *aint);
ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const char *value);
char *i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *meth, const ASN1_ENUMERATED *aint);
char *i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *meth, const ASN1_ENUMERATED *aint);
int X509V3_EXT_add(X509V3_EXT_METHOD *ext);
int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist);
int X509V3_EXT_add_alias(int nid_to, int nid_from);
void X509V3_EXT_cleanup(void);
const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext);
const X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid);
int X509V3_add_standard_extensions(void);
void *X509V3_EXT_d2i(X509_EXTENSION *ext);
X509_EXTENSION *X509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc);
int X509_check_ca(X509 *x);
int X509_check_purpose(X509 *x, int id, int ca);
int X509_supported_extension(X509_EXTENSION *ex);
int X509_PURPOSE_set(int *p, int purpose);
int X509_check_issued(X509 *issuer, X509 *subject);
int X509_check_akid(X509 *issuer, AUTHORITY_KEYID *akid);
void X509_set_proxy_flag(X509 *x);
void X509_set_proxy_pathlen(X509 *x, long l);
long X509_get_proxy_pathlen(X509 *x);
uint32_t X509_get_extension_flags(X509 *x);
uint32_t X509_get_key_usage(X509 *x);
uint32_t X509_get_extended_key_usage(X509 *x);
const ASN1_OCTET_STRING *X509_get0_subject_key_id(X509 *x);
int X509_PURPOSE_get_count(void);
X509_PURPOSE *X509_PURPOSE_get0(int idx);
int X509_PURPOSE_get_by_sname(const char *sname);
int X509_PURPOSE_get_by_id(int id);
char *X509_PURPOSE_get0_name(const X509_PURPOSE *xp);
char *X509_PURPOSE_get0_sname(const X509_PURPOSE *xp);
int X509_PURPOSE_get_trust(const X509_PURPOSE *xp);
void X509_PURPOSE_cleanup(void);
int X509_PURPOSE_get_id(const X509_PURPOSE *);
int X509_check_host(X509 *x, const char *chk, size_t chklen, unsigned int flags, char **peername);
int X509_check_email(X509 *x, const char *chk, size_t chklen, unsigned int flags);
int X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen, unsigned int flags);
int X509_check_ip_asc(X509 *x, const char *ipasc, unsigned int flags);
ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc);
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);
void X509_POLICY_NODE_print(BIO *out, X509_POLICY_NODE *node, int indent);
int X509v3_asid_add_inherit(ASIdentifiers *asid, int which);
int X509v3_asid_add_id_or_range(ASIdentifiers *asid, int which, ASN1_INTEGER *min, ASN1_INTEGER *max);
int X509v3_addr_add_inherit(IPAddrBlocks *addr, const unsigned afi, const unsigned *safi);
int X509v3_addr_add_prefix(IPAddrBlocks *addr, const unsigned afi, const unsigned *safi, unsigned char *a, const int prefixlen);
int X509v3_addr_add_range(IPAddrBlocks *addr, const unsigned afi, const unsigned *safi, unsigned char *min, unsigned char *max);
unsigned X509v3_addr_get_afi(const IPAddressFamily *f);
int X509v3_addr_get_range(IPAddressOrRange *aor, const unsigned afi, unsigned char *min, unsigned char *max, const int length);
int X509v3_asid_is_canonical(ASIdentifiers *asid);
int X509v3_addr_is_canonical(IPAddrBlocks *addr);
int X509v3_asid_canonize(ASIdentifiers *asid);
int X509v3_addr_canonize(IPAddrBlocks *addr);
int X509v3_asid_inherits(ASIdentifiers *asid);
int X509v3_addr_inherits(IPAddrBlocks *addr);
int X509v3_asid_subset(ASIdentifiers *a, ASIdentifiers *b);
int X509v3_addr_subset(IPAddrBlocks *a, IPAddrBlocks *b);
int X509v3_asid_validate_path(X509_STORE_CTX *);
int X509v3_addr_validate_path(X509_STORE_CTX *);
									  

/*----------------------------------------------------  大数操作库  ----------------------------------------------------*/
void BN_set_flags(BIGNUM *b, int n);
int BN_get_flags(const BIGNUM *b, int n);
void BN_with_flags(BIGNUM *dest, const BIGNUM *b, int flags);
int BN_GENCB_call(BN_GENCB *cb, int a, int b);
BN_GENCB *BN_GENCB_new(void);
void BN_GENCB_free(BN_GENCB *cb);
void *BN_GENCB_get_arg(BN_GENCB *cb);
int BN_abs_is_word(const BIGNUM *a, const BN_ULONG w);
int BN_is_zero(const BIGNUM *a);
int BN_is_one(const BIGNUM *a);
int BN_is_word(const BIGNUM *a, const BN_ULONG w);
int BN_is_odd(const BIGNUM *a);
void BN_zero_ex(BIGNUM *a);
const BIGNUM *BN_value_one(void);
char *BN_options(void);
BN_CTX *BN_CTX_new(void);
BN_CTX *BN_CTX_secure_new(void);
void BN_CTX_free(BN_CTX *c);
void BN_CTX_start(BN_CTX *ctx);
BIGNUM *BN_CTX_get(BN_CTX *ctx);
void BN_CTX_end(BN_CTX *ctx);
int BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_pseudo_rand(BIGNUM *rnd, int bits, int top, int bottom);
int BN_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_pseudo_rand_range(BIGNUM *rnd, const BIGNUM *range);
int BN_num_bits(const BIGNUM *a);
int BN_num_bits_word(BN_ULONG l);
int BN_security_bits(int L, int N);
BIGNUM *BN_new(void);
BIGNUM *BN_secure_new(void);
void BN_clear_free(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void BN_swap(BIGNUM *a, BIGNUM *b);
BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2bin(const BIGNUM *a, unsigned char *to);
int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
BIGNUM *BN_mpi2bn(const unsigned char *s, int len, BIGNUM *ret);
int BN_bn2mpi(const BIGNUM *a, unsigned char *to);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
void BN_set_negative(BIGNUM *b, int n);
int BN_is_negative(const BIGNUM *b);
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_add_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m);
int BN_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1(BIGNUM *r, const BIGNUM *a, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
int BN_mod_lshift(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);
BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
int BN_mul_word(BIGNUM *a, BN_ULONG w);
int BN_add_word(BIGNUM *a, BN_ULONG w);
int BN_sub_word(BIGNUM *a, BN_ULONG w);
int BN_set_word(BIGNUM *a, BN_ULONG w);
BN_ULONG BN_get_word(const BIGNUM *a);
int BN_cmp(const BIGNUM *a, const BIGNUM *b);
void BN_free(BIGNUM *a);
int BN_is_bit_set(const BIGNUM *a, int n);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
int BN_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx);
int BN_mod_exp_mont(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_mont_consttime(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont);
int BN_mod_exp_mont_word(BIGNUM *r, BN_ULONG a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1, const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx);
int BN_mask_bits(BIGNUM *a, int n);
int BN_print(BIO *bio, const BIGNUM *a);
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
void BN_clear(BIGNUM *a);
BIGNUM *BN_dup(const BIGNUM *a);
int BN_ucmp(const BIGNUM *a, const BIGNUM *b);
int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
char *BN_bn2hex(const BIGNUM *a);
char *BN_bn2dec(const BIGNUM *a);
int BN_hex2bn(BIGNUM **a, const char *str);
int BN_dec2bn(BIGNUM **a, const char *str);
int BN_asc2bn(BIGNUM **a, const char *str);
int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
BIGNUM *BN_mod_inverse(BIGNUM *ret, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
BIGNUM *BN_mod_sqrt(BIGNUM *ret, const BIGNUM *a, const BIGNUM *n, BN_CTX *ctx);
void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);
int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb);
int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
int BN_is_prime_fasttest_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, int do_trial_division, BN_GENCB *cb);
int BN_X931_generate_Xpq(BIGNUM *Xp, BIGNUM *Xq, int nbits, BN_CTX *ctx);
int BN_X931_derive_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2, const BIGNUM *Xp, const BIGNUM *Xp1, const BIGNUM *Xp2, const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb);
int BN_X931_generate_prime_ex(BIGNUM *p, BIGNUM *p1, BIGNUM *p2, BIGNUM *Xp1, BIGNUM *Xp2, const BIGNUM *Xp, const BIGNUM *e, BN_CTX *ctx, BN_GENCB *cb);
BN_MONT_CTX *BN_MONT_CTX_new(void);
int BN_mod_mul_montgomery(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_MONT_CTX *mont, BN_CTX *ctx);
int BN_to_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx);
int BN_from_montgomery(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont, BN_CTX *ctx);
void BN_MONT_CTX_free(BN_MONT_CTX *mont);
int BN_MONT_CTX_set(BN_MONT_CTX *mont, const BIGNUM *mod, BN_CTX *ctx);
BN_MONT_CTX *BN_MONT_CTX_copy(BN_MONT_CTX *to, BN_MONT_CTX *from);
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock, const BIGNUM *mod, BN_CTX *ctx);
BN_BLINDING *BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
void BN_BLINDING_free(BN_BLINDING *b);
int BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_invert(BIGNUM *n, BN_BLINDING *b, BN_CTX *ctx);
int BN_BLINDING_convert_ex(BIGNUM *n, BIGNUM *r, BN_BLINDING *b, BN_CTX *);
int BN_BLINDING_invert_ex(BIGNUM *n, const BIGNUM *r, BN_BLINDING *b, BN_CTX *);
int BN_BLINDING_is_current_thread(BN_BLINDING *b);
void BN_BLINDING_set_current_thread(BN_BLINDING *b);
int BN_BLINDING_lock(BN_BLINDING *b);
int BN_BLINDING_unlock(BN_BLINDING *b);
unsigned long BN_BLINDING_get_flags(const BN_BLINDING *);
void BN_BLINDING_set_flags(BN_BLINDING *, unsigned long);
BN_RECP_CTX *BN_RECP_CTX_new(void);
void BN_RECP_CTX_free(BN_RECP_CTX *recp);
int BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *rdiv, BN_CTX *ctx);
int BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y, BN_RECP_CTX *recp, BN_CTX *ctx);
int BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, const BIGNUM *m, BN_CTX *ctx);
int BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m, BN_RECP_CTX *recp, BN_CTX *ctx);
int BN_GF2m_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
int BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_sqr(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_sqrt(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_solve_quad(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);
int BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const int p[], BN_CTX *ctx);
int BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[], BN_CTX *ctx);
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const int p[], BN_CTX *ctx);
int BN_GF2m_mod_div_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const int p[], BN_CTX *ctx);
int BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const int p[], BN_CTX *ctx);
int BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const int p[], BN_CTX *ctx);
int BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a, const int p[], BN_CTX *ctx);
int BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
int BN_GF2m_arr2poly(const int p[], BIGNUM *a);
int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
const BIGNUM *BN_get0_nist_prime_192(void);
const BIGNUM *BN_get0_nist_prime_224(void);
const BIGNUM *BN_get0_nist_prime_256(void);
const BIGNUM *BN_get0_nist_prime_384(void);
const BIGNUM *BN_get0_nist_prime_521(void);
int BN_generate_dsa_nonce(BIGNUM *out, const BIGNUM *range, const BIGNUM *priv, const unsigned char *message, size_t message_len, BN_CTX *ctx);
BIGNUM *BN_get_rfc2409_prime_768(BIGNUM *bn);
BIGNUM *BN_get_rfc2409_prime_1024(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_1536(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_2048(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_3072(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_4096(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_6144(BIGNUM *bn);
BIGNUM *BN_get_rfc3526_prime_8192(BIGNUM *bn);
int BN_bntest_rand(BIGNUM *rnd, int bits, int top, int bottom);
int ERR_load_BN_strings(void);
BN_GFP2 *BN_GFP2_new(void);
void BN_GFP2_free(BN_GFP2 *a);
int BN_GFP2_copy(BN_GFP2 *r, const BN_GFP2 *a);
int BN_GFP2_one(BN_GFP2 *a);
int BN_GFP2_zero(BN_GFP2 *a);
int BN_GFP2_is_zero(const BN_GFP2 *a);
int BN_GFP2_equ(const BN_GFP2 *a, const BN_GFP2 *b);
int BN_GFP2_add(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_sub(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_mul(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_sqr(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_inv(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_div(BN_GFP2 *r, const BN_GFP2 *a, const BN_GFP2 *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_exp(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *k, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_set_bn(BN_GFP2 *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_add_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p,BN_CTX *ctx);
int BN_GFP2_sub_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_mul_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_GFP2_div_bn(BN_GFP2 *r, const BN_GFP2 *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
int BN_bn2gfp2(const BIGNUM *bn, BN_GFP2 *gfp2, const BIGNUM *p, BN_CTX *ctx);
int BN_gfp22bn(const BN_GFP2 *gfp2, BIGNUM *bn, const BIGNUM *p, BN_CTX *ctx);
int BN_hash_to_range(const EVP_MD *md, BIGNUM **bn, const void *in, size_t inlen, const BIGNUM *p, BN_CTX *ctx);
int BN_bn2solinas(const BIGNUM *bn, BN_SOLINAS *solinas);
int BN_solinas2bn(const BN_SOLINAS *solinas, BIGNUM *bn);
int BN_is_solinas(const BIGNUM *bn);

/*----------------------------------------------------  椭圆曲线函数  ----------------------------------------------------*/
int EC_POINT_hash2point(const EC_GROUP *group, const EVP_MD *md, const char *s, size_t slen, EC_POINT *point, BN_CTX *ctx);
EC_GROUP *EC_GROUP_new_type1curve(const BIGNUM *p, const BIGNUM *x, const BIGNUM *y, const BIGNUM *order, BN_CTX *ctx);
EC_GROUP *EC_GROUP_new_type1curve_ex(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, const unsigned char *point, size_t pointlen, const BIGNUM *order, const BIGNUM *cofactor, BN_CTX *bn_ctx);
int EC_GROUP_is_type1curve(const EC_GROUP *group, BN_CTX *ctx);
BN_GFP2 *EC_GROUP_get_type1curve_zeta(const EC_GROUP *group, BN_CTX *ctx);
BIGNUM *EC_GROUP_get_type1curve_eta(const EC_GROUP *group, BN_CTX *ctx);
int EC_type1curve_tate(const EC_GROUP *group, BN_GFP2 *r, const EC_POINT *P, const EC_POINT *Q, BN_CTX *ctx);
int EC_type1curve_tate_ratio(const EC_GROUP *group, BN_GFP2 *r, const EC_POINT *P1, const EC_POINT *Q1, const EC_POINT *P2, const EC_POINT *Q2, BN_CTX *bn_ctx);
const EC_METHOD *EC_GFp_simple_method(void);
const EC_METHOD *EC_GFp_mont_method(void);
const EC_METHOD *EC_GFp_nist_method(void);
const EC_METHOD *EC_GF2m_simple_method(void);
EC_GROUP *EC_GROUP_new(const EC_METHOD *meth);
void EC_GROUP_free(EC_GROUP *group);
void EC_GROUP_clear_free(EC_GROUP *group);
int EC_GROUP_copy(EC_GROUP *dst, const EC_GROUP *src);
EC_GROUP *EC_GROUP_dup(const EC_GROUP *src);
const EC_METHOD *EC_GROUP_method_of(const EC_GROUP *group);
int EC_METHOD_get_field_type(const EC_METHOD *meth);
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);
BN_MONT_CTX *EC_GROUP_get_mont_data(const EC_GROUP *group);
int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);
const BIGNUM *EC_GROUP_get0_order(const EC_GROUP *group);
int EC_GROUP_order_bits(const EC_GROUP *group);
int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx);
const BIGNUM *EC_GROUP_get0_cofactor(const EC_GROUP *group);
void EC_GROUP_set_curve_name(EC_GROUP *group, int nid);
int EC_GROUP_get_curve_name(const EC_GROUP *group);
void EC_GROUP_set_asn1_flag(EC_GROUP *group, int flag);
int EC_GROUP_get_asn1_flag(const EC_GROUP *group);
void EC_GROUP_set_point_conversion_form(EC_GROUP *group, point_conversion_form_t form);
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);
unsigned char *EC_GROUP_get0_seed(const EC_GROUP *x);
size_t EC_GROUP_get_seed_len(const EC_GROUP *);
size_t EC_GROUP_set_seed(EC_GROUP *, const unsigned char *, size_t len);
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_set_curve_GF2m(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_get_curve_GF2m(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
int EC_GROUP_get_degree(const EC_GROUP *group);
int EC_GROUP_check(const EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_check_discriminant(const EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_cmp(const EC_GROUP *a, const EC_GROUP *b, BN_CTX *ctx);
EC_GROUP *EC_GROUP_new_curve_GFp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
EC_GROUP *EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
EC_GROUP *EC_GROUP_new_from_ecparameters(const ECPARAMETERS *params);
ECPARAMETERS *EC_GROUP_get_ecparameters(const EC_GROUP *group, ECPARAMETERS *params);
EC_GROUP *EC_GROUP_new_from_ecpkparameters(const ECPKPARAMETERS *params);
ECPKPARAMETERS *EC_GROUP_get_ecpkparameters(const EC_GROUP *group, ECPKPARAMETERS *params);
void EC_POINT_free(EC_POINT *point);
void EC_POINT_clear_free(EC_POINT *point);
int EC_POINT_copy(EC_POINT *dst, const EC_POINT *src);
EC_POINT *EC_POINT_dup(const EC_POINT *src, const EC_GROUP *group);
const EC_METHOD *EC_POINT_method_of(const EC_POINT *point);
int EC_POINT_set_to_infinity(const EC_GROUP *group, EC_POINT *point);
int EC_POINT_set_Jprojective_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, const BIGNUM *z, BN_CTX *ctx);
int EC_POINT_get_Jprojective_coordinates_GFp(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BIGNUM *z, BN_CTX *ctx);
int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
int EC_POINT_get_affine_coordinates_GFp(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
int EC_POINT_set_compressed_coordinates_GFp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, int y_bit, BN_CTX *ctx);
int EC_POINT_set_affine_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
int EC_POINT_get_affine_coordinates_GF2m(const EC_GROUP *group, const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
int EC_POINT_set_compressed_coordinates_GF2m(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, int y_bit, BN_CTX *ctx);
size_t EC_POINT_point2oct(const EC_GROUP *group, const EC_POINT *p, point_conversion_form_t form, unsigned char *buf, size_t len, BN_CTX *ctx);
int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p, const unsigned char *buf, size_t len, BN_CTX *ctx);
size_t EC_POINT_point2buf(const EC_GROUP *group, const EC_POINT *point, point_conversion_form_t form, unsigned char **pbuf, BN_CTX *ctx);
BIGNUM *EC_POINT_point2bn(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form, BIGNUM *, BN_CTX *);
EC_POINT *EC_POINT_bn2point(const EC_GROUP *, const BIGNUM *, EC_POINT *, BN_CTX *);
char *EC_POINT_point2hex(const EC_GROUP *, const EC_POINT *, point_conversion_form_t form, BN_CTX *);
EC_POINT *EC_POINT_hex2point(const EC_GROUP *, const char *, EC_POINT *, BN_CTX *);
int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, BN_CTX *ctx);
int EC_POINT_invert(const EC_GROUP *group, EC_POINT *a, BN_CTX *ctx);
int EC_POINT_is_at_infinity(const EC_GROUP *group, const EC_POINT *p);
int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx);
int EC_POINT_cmp(const EC_GROUP *group, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);
int EC_POINT_make_affine(const EC_GROUP *group, EC_POINT *point, BN_CTX *ctx);
int EC_POINTs_make_affine(const EC_GROUP *group, size_t num, EC_POINT *points[], BN_CTX *ctx);
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, size_t num, const EC_POINT *p[], const BIGNUM *m[], BN_CTX *ctx);
int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx);
int EC_GROUP_have_precompute_mult(const EC_GROUP *group);
int EC_GROUP_get_basis_type(const EC_GROUP *);
int EC_GROUP_get_trinomial_basis(const EC_GROUP *, unsigned int *k);
int EC_GROUP_get_pentanomial_basis(const EC_GROUP *, unsigned int *k1, unsigned int *k2, unsigned int *k3);
EC_GROUP *d2i_ECPKParameters(EC_GROUP **, const unsigned char **in, long len);
int i2d_ECPKParameters(const EC_GROUP *, unsigned char **out);
int ECPKParameters_print(BIO *bp, const EC_GROUP *x, int off);
EC_KEY *EC_KEY_new(void);
int EC_KEY_get_flags(const EC_KEY *key);
void EC_KEY_set_flags(EC_KEY *key, int flags);
void EC_KEY_clear_flags(EC_KEY *key, int flags);
EC_KEY *EC_KEY_new_by_curve_name(int nid);
void EC_KEY_free(EC_KEY *key);
EC_KEY *EC_KEY_copy(EC_KEY *dst, const EC_KEY *src);
EC_KEY *EC_KEY_dup(const EC_KEY *src);
int EC_KEY_up_ref(EC_KEY *key);
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);
int EC_KEY_set_group(EC_KEY *key, const EC_GROUP *group);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *key);
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *key);
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);
unsigned EC_KEY_get_enc_flags(const EC_KEY *key);
void EC_KEY_set_enc_flags(EC_KEY *eckey, unsigned int flags);
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);
void EC_KEY_set_conv_form(EC_KEY *eckey, point_conversion_form_t cform);
int EC_KEY_set_ex_data(EC_KEY *key, int idx, void *arg);
void *EC_KEY_get_ex_data(const EC_KEY *key, int idx);
void EC_KEY_set_asn1_flag(EC_KEY *eckey, int asn1_flag);
int EC_KEY_precompute_mult(EC_KEY *key, BN_CTX *ctx);
int EC_KEY_generate_key(EC_KEY *key);
int EC_KEY_check_key(const EC_KEY *key);
int EC_KEY_can_sign(const EC_KEY *eckey);
int EC_KEY_set_public_key_affine_coordinates(EC_KEY *key, BIGNUM *x, BIGNUM *y);
size_t EC_KEY_key2buf(const EC_KEY *key, point_conversion_form_t form, unsigned char **pbuf, BN_CTX *ctx);
int EC_KEY_oct2key(EC_KEY *key, const unsigned char *buf, size_t len, BN_CTX *ctx);
int EC_KEY_oct2priv(EC_KEY *key, const unsigned char *buf, size_t len);
size_t EC_KEY_priv2oct(const EC_KEY *key, unsigned char *buf, size_t len);
size_t EC_KEY_priv2buf(const EC_KEY *eckey, unsigned char **pbuf);
EC_KEY *d2i_ECPrivateKey(EC_KEY **key, const unsigned char **in, long len);
int i2d_ECPrivateKey(EC_KEY *key, unsigned char **out);
EC_KEY *d2i_ECParameters(EC_KEY **key, const unsigned char **in, long len);
int i2d_ECParameters(EC_KEY *key, unsigned char **out);
EC_KEY *o2i_ECPublicKey(EC_KEY **key, const unsigned char **in, long len);
int i2o_ECPublicKey(const EC_KEY *key, unsigned char **out);
int ECParameters_print(BIO *bp, const EC_KEY *key);
int EC_KEY_print(BIO *bp, const EC_KEY *key, int off);
const EC_KEY_METHOD *EC_KEY_OpenSSL(void);
const EC_KEY_METHOD *EC_KEY_get_default_method(void);
void EC_KEY_set_default_method(const EC_KEY_METHOD *meth);
const EC_KEY_METHOD *EC_KEY_get_method(const EC_KEY *key);
int EC_KEY_set_method(EC_KEY *key, const EC_KEY_METHOD *meth);
EC_KEY *EC_KEY_new_method(ENGINE *engine);
int ECDH_KDF_X9_62(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, const unsigned char *sinfo, size_t sinfolen, const EVP_MD *md);
ECDSA_SIG *ECDSA_SIG_new(void);
void ECDSA_SIG_free(ECDSA_SIG *sig);
int i2d_ECDSA_SIG(const ECDSA_SIG *sig, unsigned char **pp);
ECDSA_SIG *d2i_ECDSA_SIG(ECDSA_SIG **sig, const unsigned char **pp, long len);
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
ECDSA_SIG *ECDSA_do_sign(const unsigned char *dgst, int dgst_len, EC_KEY *eckey);
ECDSA_SIG *ECDSA_do_sign_ex(const unsigned char *dgst, int dgstlen, const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);
int ECDSA_do_verify(const unsigned char *dgst, int dgst_len, const ECDSA_SIG *sig, EC_KEY *eckey);
int ECDSA_sign_setup(EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv, BIGNUM **rp);
int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
int ECDSA_sign_ex(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *rp, EC_KEY *eckey);
int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char *sig, int siglen, EC_KEY *eckey);
int ECDSA_size(const EC_KEY *eckey);
EC_KEY_METHOD *EC_KEY_METHOD_new(const EC_KEY_METHOD *meth);
void EC_KEY_METHOD_free(EC_KEY_METHOD *meth);
int ERR_load_EC_strings(void);

/*----------------------------------------------------  AES  ----------------------------------------------------*/
const char *AES_options(void);
int AES_set_encrypt_key(const unsigned char *userKey, const unsigned int bits, AES_KEY *key);
int AES_set_decrypt_key(const unsigned char *userKey, const int bits, AES_KEY *key);
void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_decrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key);
void AES_ecb_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key, const int enc);
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, const int enc);
void AES_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, int *num, const int enc);
void AES_cfb1_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, int *num, const int enc);
void AES_cfb8_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, int *num, const int enc);
void AES_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, int *num);
void AES_ige_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, unsigned char *ivec, const int enc);
void AES_bi_ige_encrypt(const unsigned char *in, unsigned char *out, size_t length, const AES_KEY *key, const AES_KEY *key2, const unsigned char *ivec, const int enc);
int AES_wrap_key(AES_KEY *key, const unsigned char *iv, unsigned char *out, const unsigned char *in, unsigned int inlen);
int AES_unwrap_key(AES_KEY *key, const unsigned char *iv, unsigned char *out, const unsigned char *in, unsigned int inlen);

/*----------------------------------------------------  BB1IBE  ----------------------------------------------------*/				   
int BB1IBE_setup(const EC_GROUP *group, const EVP_MD *md, BB1PublicParameters **mpk, BB1MasterSecret **msk);
BB1PrivateKeyBlock *BB1IBE_extract_private_key(BB1PublicParameters *mpk, BB1MasterSecret *msk, const char *id, size_t idlen);
BB1CiphertextBlock *BB1IBE_do_encrypt(BB1PublicParameters *mpk, const unsigned char *in, size_t inlen, const char *id, size_t idlen);
int BB1IBE_do_decrypt(BB1PublicParameters *mpk, const BB1CiphertextBlock *in, unsigned char *out, size_t *outlen, BB1PrivateKeyBlock *sk);
int BB1IBE_encrypt(BB1PublicParameters *mpk, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, const char *id, size_t idlen);
int BB1IBE_decrypt(BB1PublicParameters *mpk, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, BB1PrivateKeyBlock *sk);
int ERR_load_BB1IBE_strings(void);

/*----------------------------------------------------  BFIBE  ----------------------------------------------------*/
int BFIBE_setup(const EC_GROUP *group, const EVP_MD *md, BFPublicParameters **mpk, BFMasterSecret **msk);
BFPrivateKeyBlock *BFIBE_extract_private_key(BFPublicParameters *mpk, BFMasterSecret *msk, const char *id, size_t idlen);
BFCiphertextBlock *BFIBE_do_encrypt(BFPublicParameters *mpk, const unsigned char *in, size_t inlen, const char *id, size_t idlen);
int BFIBE_do_decrypt(BFPublicParameters *mpk, const BFCiphertextBlock *in, unsigned char *out, size_t *outlen, BFPrivateKeyBlock *sk);
int BFIBE_encrypt(BFPublicParameters *mpk, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, const char *id, size_t idlen);
int BFIBE_decrypt(BFPublicParameters *mpk, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, BFPrivateKeyBlock *sk);
int ERR_load_BFIBE_strings(void);

/*----------------------------------------------------  BLOWFISH  ----------------------------------------------------*/
void BF_set_key(BF_KEY *key, int len, const unsigned char *data);
void BF_encrypt(BF_LONG *data, const BF_KEY *key);
void BF_decrypt(BF_LONG *data, const BF_KEY *key);
void BF_ecb_encrypt(const unsigned char *in, unsigned char *out, const BF_KEY *key, int enc);
void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, const BF_KEY *schedule, unsigned char *ivec, int enc);
void BF_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, const BF_KEY *schedule, unsigned char *ivec, int *num, int enc);
void BF_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, const BF_KEY *schedule, unsigned char *ivec, int *num);
const char *BF_options(void);

/*----------------------------------------------------  CAMELLIA  ----------------------------------------------------*/
int Camellia_set_key(const unsigned char *userKey, const int bits, CAMELLIA_KEY *key);
void Camellia_encrypt(const unsigned char *in, unsigned char *out, const CAMELLIA_KEY *key);
void Camellia_decrypt(const unsigned char *in, unsigned char *out, const CAMELLIA_KEY *key);
void Camellia_ecb_encrypt(const unsigned char *in, unsigned char *out, const CAMELLIA_KEY *key, const int enc);
void Camellia_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t length, const CAMELLIA_KEY *key, unsigned char *ivec, const int enc);
void Camellia_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const CAMELLIA_KEY *key, unsigned char *ivec, int *num, const int enc);
void Camellia_cfb1_encrypt(const unsigned char *in, unsigned char *out, size_t length, const CAMELLIA_KEY *key, unsigned char *ivec, int *num, const int enc);
void Camellia_cfb8_encrypt(const unsigned char *in, unsigned char *out, size_t length, const CAMELLIA_KEY *key, unsigned char *ivec, int *num, const int enc);
void Camellia_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const CAMELLIA_KEY *key, unsigned char *ivec, int *num);
void Camellia_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t length, const CAMELLIA_KEY *key, unsigned char ivec[CAMELLIA_BLOCK_SIZE], unsigned char ecount_buf[CAMELLIA_BLOCK_SIZE], unsigned int *num);

/*----------------------------------------------------  CAST  ----------------------------------------------------*/
void CAST_set_key(CAST_KEY *key, int len, const unsigned char *data);
void CAST_ecb_encrypt(const unsigned char *in, unsigned char *out, const CAST_KEY *key, int enc);
void CAST_encrypt(CAST_LONG *data, const CAST_KEY *key);
void CAST_decrypt(CAST_LONG *data, const CAST_KEY *key);
void CAST_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, const CAST_KEY *ks, unsigned char *iv, int enc);
void CAST_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, const CAST_KEY *schedule, unsigned char *ivec, int *num, int enc);
void CAST_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, const CAST_KEY *schedule, unsigned char *ivec, int *num);

/*----------------------------------------------------  CMAC  ----------------------------------------------------*/
CMAC_CTX *CMAC_CTX_new(void);
void CMAC_CTX_cleanup(CMAC_CTX *ctx);
void CMAC_CTX_free(CMAC_CTX *ctx);
EVP_CIPHER_CTX *CMAC_CTX_get0_cipher_ctx(CMAC_CTX *ctx);
int CMAC_CTX_copy(CMAC_CTX *out, const CMAC_CTX *in);
int CMAC_Init(CMAC_CTX *ctx, const void *key, size_t keylen, const EVP_CIPHER *cipher, ENGINE *impl);
int CMAC_Update(CMAC_CTX *ctx, const void *data, size_t dlen);
int CMAC_Final(CMAC_CTX *ctx, unsigned char *out, size_t *poutlen);
int CMAC_resume(CMAC_CTX *ctx);

/*----------------------------------------------------  CPK  ----------------------------------------------------*/
X509_ALGOR *CPK_MAP_new_default(void);
int CPK_MAP_is_valid(const X509_ALGOR *algor);
int CPK_MAP_num_factors(const X509_ALGOR *algor);
int CPK_MAP_num_indexes(const X509_ALGOR *algor);
int CPK_MAP_str2index(const X509_ALGOR *algor, const char *str, int *index);
CPK_MASTER_SECRET *CPK_MASTER_SECRET_create(const char *domain_id, EVP_PKEY *pkey, X509_ALGOR *map_algor);
CPK_PUBLIC_PARAMS *CPK_MASTER_SECRET_extract_public_params(CPK_MASTER_SECRET *master);
EVP_PKEY *CPK_MASTER_SECRET_extract_private_key(CPK_MASTER_SECRET *master, const char *id);
EVP_PKEY *CPK_PUBLIC_PARAMS_extract_public_key(CPK_PUBLIC_PARAMS *params, const char *id);
char *CPK_MASTER_SECRET_get_name(CPK_MASTER_SECRET *master, char *buf, int size);
char *CPK_PUBLIC_PARAMS_get_name(CPK_PUBLIC_PARAMS *params, char *buf, int size);
int CPK_MASTER_SECRET_digest(CPK_MASTER_SECRET *master, const EVP_MD *type, unsigned char *md, unsigned int *len);
int CPK_PUBLIC_PARAMS_digest(CPK_PUBLIC_PARAMS *params, const EVP_MD *type, unsigned char *md, unsigned int *len);
int CPK_MASTER_SECRET_print(BIO *out, CPK_MASTER_SECRET *master, int indent, unsigned long flags);
int CPK_PUBLIC_PARAMS_print(BIO *out, CPK_PUBLIC_PARAMS *params, int indent, unsigned long flags);
int CPK_MASTER_SECRET_validate_public_params(CPK_MASTER_SECRET *master, CPK_PUBLIC_PARAMS *params);
int CPK_PUBLIC_PARAMS_validate_private_key(CPK_PUBLIC_PARAMS *params, const char *id, const EVP_PKEY *pkey);
CPK_MASTER_SECRET *d2i_CPK_MASTER_SECRET_bio(BIO *bp, CPK_MASTER_SECRET **master);
int i2d_CPK_MASTER_SECRET_bio(BIO *bp, CPK_MASTER_SECRET *master);
CPK_PUBLIC_PARAMS *d2i_CPK_PUBLIC_PARAMS_bio(BIO *bp, CPK_PUBLIC_PARAMS **params);
int i2d_CPK_PUBLIC_PARAMS_bio(BIO *bp, CPK_PUBLIC_PARAMS *params);
int ERR_load_CPK_strings(void);

/*----------------------------------------------------  DES  ----------------------------------------------------*/
const char *DES_options(void);
void DES_ecb3_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3, int enc);
DES_LONG DES_cbc_cksum(const unsigned char *input, DES_cblock *output, long length, DES_key_schedule *schedule, const_DES_cblock *ivec);
void DES_cbc_encrypt(const unsigned char *input, unsigned char *output, long length, DES_key_schedule *schedule, DES_cblock *ivec, int enc);
void DES_ncbc_encrypt(const unsigned char *input, unsigned char *output, long length, DES_key_schedule *schedule, DES_cblock *ivec, int enc);
void DES_xcbc_encrypt(const unsigned char *input, unsigned char *output, long length, DES_key_schedule *schedule, DES_cblock *ivec, const_DES_cblock *inw, const_DES_cblock *outw, int enc);
void DES_cfb_encrypt(const unsigned char *in, unsigned char *out, int numbits, long length, DES_key_schedule *schedule, DES_cblock *ivec, int enc);
void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc);
void DES_encrypt1(DES_LONG *data, DES_key_schedule *ks, int enc);
void DES_encrypt2(DES_LONG *data, DES_key_schedule *ks, int enc);
void DES_encrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_decrypt3(DES_LONG *data, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3);
void DES_ede3_cbc_encrypt(const unsigned char *input, unsigned char *output, long length, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3, DES_cblock *ivec, int enc);
void DES_ede3_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3, DES_cblock *ivec, int *num, int enc);
void DES_ede3_cfb_encrypt(const unsigned char *in, unsigned char *out, int numbits, long length, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3, DES_cblock *ivec, int enc);
void DES_ede3_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, DES_key_schedule *ks1, DES_key_schedule *ks2, DES_key_schedule *ks3, DES_cblock *ivec, int *num);
char *DES_fcrypt(const char *buf, const char *salt, char *ret);
char *DES_crypt(const char *buf, const char *salt);
void DES_ofb_encrypt(const unsigned char *in, unsigned char *out, int numbits, long length, DES_key_schedule *schedule, DES_cblock *ivec);
void DES_pcbc_encrypt(const unsigned char *input, unsigned char *output, long length, DES_key_schedule *schedule, DES_cblock *ivec, int enc);
DES_LONG DES_quad_cksum(const unsigned char *input, DES_cblock output[], long length, int out_count, DES_cblock *seed);
int DES_random_key(DES_cblock *ret);
void DES_set_odd_parity(DES_cblock *key);
int DES_check_key_parity(const_DES_cblock *key);
int DES_is_weak_key(const_DES_cblock *key);
int DES_set_key(const_DES_cblock *key, DES_key_schedule *schedule);
int DES_key_sched(const_DES_cblock *key, DES_key_schedule *schedule);
int DES_set_key_checked(const_DES_cblock *key, DES_key_schedule *schedule);
void DES_set_key_unchecked(const_DES_cblock *key, DES_key_schedule *schedule);
void DES_string_to_key(const char *str, DES_cblock *key);
void DES_string_to_2keys(const char *str, DES_cblock *key1, DES_cblock *key2);
void DES_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, DES_key_schedule *schedule, DES_cblock *ivec, int *num, int enc);
void DES_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, DES_key_schedule *schedule, DES_cblock *ivec, int *num);

/*----------------------------------------------------  DH  ----------------------------------------------------*/
DH *DHparams_dup(DH *);
const DH_METHOD *DH_OpenSSL(void);
void DH_set_default_method(const DH_METHOD *meth);
const DH_METHOD *DH_get_default_method(void);
int DH_set_method(DH *dh, const DH_METHOD *meth);
DH *DH_new_method(ENGINE *engine);
DH *DH_new(void);
void DH_free(DH *dh);
int DH_up_ref(DH *dh);
int DH_bits(const DH *dh);
int DH_size(const DH *dh);
int DH_security_bits(const DH *dh);
int DH_set_ex_data(DH *d, int idx, void *arg);
void *DH_get_ex_data(DH *d, int idx);
int DH_generate_parameters_ex(DH *dh, int prime_len, int generator, BN_GENCB *cb);
int DH_check_params(const DH *dh, int *ret);
int DH_check(const DH *dh, int *codes);
int DH_check_pub_key(const DH *dh, const BIGNUM *pub_key, int *codes);
int DH_generate_key(DH *dh);
int DH_compute_key(unsigned char *key, const BIGNUM *pub_key, DH *dh);
int DH_compute_key_padded(unsigned char *key, const BIGNUM *pub_key, DH *dh);
DH *d2i_DHparams(DH **a, const unsigned char **pp, long length);
int i2d_DHparams(const DH *a, unsigned char **pp);
DH *d2i_DHxparams(DH **a, const unsigned char **pp, long length);
int i2d_DHxparams(const DH *a, unsigned char **pp);
int DHparams_print(BIO *bp, const DH *x);
DH *DH_get_1024_160(void);
DH *DH_get_2048_224(void);
DH *DH_get_2048_256(void);
int DH_KDF_X9_42(unsigned char *out, size_t outlen, const unsigned char *Z, size_t Zlen, ASN1_OBJECT *key_oid, const unsigned char *ukm, size_t ukmlen, const EVP_MD *md);
void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key);
int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key);
void DH_clear_flags(DH *dh, int flags);
int DH_test_flags(const DH *dh, int flags);
void DH_set_flags(DH *dh, int flags);
ENGINE *DH_get0_engine(DH *d);
long DH_get_length(const DH *dh);
int DH_set_length(DH *dh, long length);
DH_METHOD *DH_meth_new(const char *name, int flags);
void DH_meth_free(DH_METHOD *dhm);
DH_METHOD *DH_meth_dup(const DH_METHOD *dhm);
const char *DH_meth_get0_name(const DH_METHOD *dhm);
int DH_meth_set1_name(DH_METHOD *dhm, const char *name);
int DH_meth_get_flags(DH_METHOD *dhm);
int DH_meth_set_flags(DH_METHOD *dhm, int flags);
void *DH_meth_get0_app_data(const DH_METHOD *dhm);
int DH_meth_set0_app_data(DH_METHOD *dhm, void *app_data);
int ERR_load_DH_strings(void);

/*----------------------------------------------------  DSA  ----------------------------------------------------*/
DSA *DSAparams_dup(DSA *x);
DSA_SIG *DSA_SIG_new(void);
void DSA_SIG_free(DSA_SIG *a);
int i2d_DSA_SIG(const DSA_SIG *a, unsigned char **pp);
DSA_SIG *d2i_DSA_SIG(DSA_SIG **v, const unsigned char **pp, long length);
void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);
DSA_SIG *DSA_do_sign(const unsigned char *dgst, int dlen, DSA *dsa);
int DSA_do_verify(const unsigned char *dgst, int dgst_len, DSA_SIG *sig, DSA *dsa);
const DSA_METHOD *DSA_OpenSSL(void);
void DSA_set_default_method(const DSA_METHOD *);
const DSA_METHOD *DSA_get_default_method(void);
int DSA_set_method(DSA *dsa, const DSA_METHOD *);
const DSA_METHOD *DSA_get_method(DSA *d);
DSA *DSA_new(void);
DSA *DSA_new_method(ENGINE *engine);
void DSA_free(DSA *r);
int DSA_up_ref(DSA *r);
int DSA_size(const DSA *);
int DSA_bits(const DSA *d);
int DSA_security_bits(const DSA *d);
int DSA_sign_setup(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);
int DSA_sign(int type, const unsigned char *dgst, int dlen, unsigned char *sig, unsigned int *siglen, DSA *dsa);
int DSA_verify(int type, const unsigned char *dgst, int dgst_len, const unsigned char *sigbuf, int siglen, DSA *dsa);
int DSA_set_ex_data(DSA *d, int idx, void *arg);
void *DSA_get_ex_data(DSA *d, int idx);
DSA *d2i_DSAPublicKey(DSA **a, const unsigned char **pp, long length);
DSA *d2i_DSAPrivateKey(DSA **a, const unsigned char **pp, long length);
DSA *d2i_DSAparams(DSA **a, const unsigned char **pp, long length);
int DSA_generate_parameters_ex(DSA *dsa, int bits, const unsigned char *seed, int seed_len, int *counter_ret, unsigned long *h_ret, BN_GENCB *cb);
int DSA_generate_key(DSA *a);
int i2d_DSAPublicKey(const DSA *a, unsigned char **pp);
int i2d_DSAPrivateKey(const DSA *a, unsigned char **pp);
int i2d_DSAparams(const DSA *a, unsigned char **pp);
int DSAparams_print(BIO *bp, const DSA *x);
int DSA_print(BIO *bp, const DSA *x, int off);
DH *DSA_dup_DH(const DSA *r);
void DSA_get0_pqg(const DSA *d, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key);
int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key);
void DSA_clear_flags(DSA *d, int flags);
int DSA_test_flags(const DSA *d, int flags);
void DSA_set_flags(DSA *d, int flags);
ENGINE *DSA_get0_engine(DSA *d);
DSA_METHOD *DSA_meth_new(const char *name, int flags);
void DSA_meth_free(DSA_METHOD *dsam);
DSA_METHOD *DSA_meth_dup(const DSA_METHOD *dsam);
const char *DSA_meth_get0_name(const DSA_METHOD *dsam);
int DSA_meth_set1_name(DSA_METHOD *dsam, const char *name);
int DSA_meth_get_flags(DSA_METHOD *dsam);
int DSA_meth_set_flags(DSA_METHOD *dsam, int flags);
void *DSA_meth_get0_app_data(const DSA_METHOD *dsam);
int DSA_meth_set0_app_data(DSA_METHOD *dsam, void *app_data);
int ERR_load_DSA_strings(void);

/*----------------------------------------------------  ECIES  ----------------------------------------------------*/
int ECIES_PARAMS_init_with_recommended(ECIES_PARAMS *param);
int ECIES_PARAMS_init_with_type(ECIES_PARAMS *param, int type);
KDF_FUNC ECIES_PARAMS_get_kdf(const ECIES_PARAMS *param);
int ECIES_PARAMS_get_enc(const ECIES_PARAMS *param, size_t inlen, const EVP_CIPHER **enc_cipher, size_t *enckeylen, size_t *ciphertextlen);
int ECIES_PARAMS_get_mac(const ECIES_PARAMS *param, const EVP_MD **hmac_md, const EVP_CIPHER **cmac_cipher, unsigned int *mackeylen, unsigned int *maclen);
int i2d_ECIESParameters(const ECIES_PARAMS *param, unsigned char **out);
ECIES_PARAMS *d2i_ECIESParameters(ECIES_PARAMS **param, const unsigned char **in, long len);
int ECIES_CIPHERTEXT_VALUE_ciphertext_length(const ECIES_CIPHERTEXT_VALUE *a);
ECIES_CIPHERTEXT_VALUE *ECIES_do_encrypt(const ECIES_PARAMS *param, const unsigned char *in, size_t inlen, EC_KEY *ec_key);
int ECIES_do_decrypt(const ECIES_PARAMS *param, const ECIES_CIPHERTEXT_VALUE *in, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int ECIES_encrypt(int param, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int ECIES_decrypt(int param, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);

/*----------------------------------------------------  FFX  ----------------------------------------------------*/
FFX_CTX *FFX_CTX_new(void);
void FFX_CTX_free(FFX_CTX *ctx);
int FFX_init(FFX_CTX *ctx, const EVP_CIPHER *cipher, const unsigned char *key, int flag);
int FFX_encrypt(FFX_CTX *ctx, const char *in, char *out, size_t iolen, unsigned char *tweak, size_t tweaklen);
int FFX_decrypt(FFX_CTX *ctx, const char *in, char *out, size_t iolen, unsigned char *tweak, size_t tweaklen);
int FFX_compute_luhn(const char *in, size_t inlen);

/*----------------------------------------------------  HKDF  ----------------------------------------------------*/
/*
unsigned char *HKDF(const EVP_MD *evp_md, const unsigned char *salt, size_t salt_len, const unsigned char *key, size_t key_len, const unsigned char *info, size_t info_len, unsigned char *okm, size_t okm_len);
unsigned char *HKDF_Extract(const EVP_MD *evp_md, const unsigned char *salt, size_t salt_len, const unsigned char *key, size_t key_len, unsigned char *prk, size_t *prk_len);
unsigned char *HKDF_Expand(const EVP_MD *evp_md, const unsigned char *prk, size_t prk_len, const unsigned char *info, size_t info_len, unsigned char *okm, size_t okm_len);
*/
/*----------------------------------------------------  HMAC  ----------------------------------------------------*/						   
size_t HMAC_size(const HMAC_CTX *e);
HMAC_CTX *HMAC_CTX_new(void);
int HMAC_CTX_reset(HMAC_CTX *ctx);
void HMAC_CTX_free(HMAC_CTX *ctx);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len, const unsigned char *d, size_t n, unsigned char *md, unsigned int *md_len);
int HMAC_CTX_copy(HMAC_CTX *dctx, HMAC_CTX *sctx);
void HMAC_CTX_set_flags(HMAC_CTX *ctx, unsigned long flags);
const EVP_MD *HMAC_CTX_get_md(const HMAC_CTX *ctx);
				
/*----------------------------------------------------  IDEA  ----------------------------------------------------*/
const char *IDEA_options(void);
void IDEA_ecb_encrypt(const unsigned char *in, unsigned char *out, IDEA_KEY_SCHEDULE *ks);
void IDEA_set_encrypt_key(const unsigned char *key, IDEA_KEY_SCHEDULE *ks);
void IDEA_set_decrypt_key(IDEA_KEY_SCHEDULE *ek, IDEA_KEY_SCHEDULE *dk);
void IDEA_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int enc);
void IDEA_cfb64_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int *num, int enc);
void IDEA_ofb64_encrypt(const unsigned char *in, unsigned char *out, long length, IDEA_KEY_SCHEDULE *ks, unsigned char *iv, int *num);
void IDEA_encrypt(unsigned long *in, IDEA_KEY_SCHEDULE *ks);

/*----------------------------------------------------  LHASH  ----------------------------------------------------*/
int OPENSSL_LH_error(OPENSSL_LHASH *lh);
OPENSSL_LHASH *OPENSSL_LH_new(OPENSSL_LH_HASHFUNC h, OPENSSL_LH_COMPFUNC c);
void OPENSSL_LH_free(OPENSSL_LHASH *lh);
void *OPENSSL_LH_insert(OPENSSL_LHASH *lh, void *data);
void *OPENSSL_LH_delete(OPENSSL_LHASH *lh, const void *data);
void *OPENSSL_LH_retrieve(OPENSSL_LHASH *lh, const void *data);
void OPENSSL_LH_doall(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNC func);
void OPENSSL_LH_doall_arg(OPENSSL_LHASH *lh, OPENSSL_LH_DOALL_FUNCARG func, void *arg);
unsigned long OPENSSL_LH_strhash(const char *c);
unsigned long OPENSSL_LH_num_items(const OPENSSL_LHASH *lh);
unsigned long OPENSSL_LH_get_down_load(const OPENSSL_LHASH *lh);
void OPENSSL_LH_set_down_load(OPENSSL_LHASH *lh, unsigned long down_load);
void OPENSSL_LH_stats(const OPENSSL_LHASH *lh, FILE *fp);
void OPENSSL_LH_node_stats(const OPENSSL_LHASH *lh, FILE *fp);
void OPENSSL_LH_node_usage_stats(const OPENSSL_LHASH *lh, FILE *fp);
void OPENSSL_LH_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
void OPENSSL_LH_node_stats_bio(const OPENSSL_LHASH *lh, BIO *out);
void OPENSSL_LH_node_usage_stats_bio(const OPENSSL_LHASH *lh, BIO *out);

/*----------------------------------------------------  MD  ----------------------------------------------------*/
/*
const char *MD2_options(void);
int MD2_Init(MD2_CTX *c);
int MD2_Update(MD2_CTX *c, const unsigned char *data, size_t len);
int MD2_Final(unsigned char *md, MD2_CTX *c);
unsigned char *MD2(const unsigned char *d, size_t n, unsigned char *md);
*/
int MD4_Init(MD4_CTX *c);
int MD4_Update(MD4_CTX *c, const void *data, size_t len);
int MD4_Final(unsigned char *md, MD4_CTX *c);
unsigned char *MD4(const unsigned char *d, size_t n, unsigned char *md);
void MD4_Transform(MD4_CTX *c, const unsigned char *b);
int MD5_Init(MD5_CTX *c);
int MD5_Update(MD5_CTX *c, const void *data, size_t len);
int MD5_Final(unsigned char *md, MD5_CTX *c);
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
void MD5_Transform(MD5_CTX *c, const unsigned char *b);

/*----------------------------------------------------  MDC2  ----------------------------------------------------*/
int MDC2_Init(MDC2_CTX *c);
int MDC2_Update(MDC2_CTX *c, const unsigned char *data, size_t len);
int MDC2_Final(unsigned char *md, MDC2_CTX *c);
unsigned char *MDC2(const unsigned char *d, size_t n, unsigned char *md);

/*----------------------------------------------------  MODES  ----------------------------------------------------*/
void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], block128_f block);
void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], unsigned char ecount_buf[16], unsigned int *num, block128_f block);
void CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], unsigned char ecount_buf[16], unsigned int *num, ctr128_f ctr);
void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], int *num, block128_f block);
void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], int *num, int enc, block128_f block);
void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out, size_t length, const void *key,  unsigned char ivec[16], int *num,  int enc, block128_f block);
void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out, size_t bits, const void *key, unsigned char ivec[16], int *num, int enc, block128_f block);
size_t CRYPTO_cts128_encrypt_block(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], block128_f block);
size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_cts128_decrypt_block(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], block128_f block);
size_t CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_nistcts128_encrypt_block(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], block128_f block);
size_t CRYPTO_nistcts128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_nistcts128_decrypt_block(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], block128_f block);
size_t CRYPTO_nistcts128_decrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char ivec[16], cbc128_f cbc);
GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block);
void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block);
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv, size_t len);
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad, size_t len);
int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx, const unsigned char *in, unsigned char *out, size_t len);
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx, const unsigned char *in, unsigned char *out, size_t len);
int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx, const unsigned char *in, unsigned char *out, size_t len, ctr128_f stream);
int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx, const unsigned char *in, unsigned char *out, size_t len, ctr128_f stream);
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const unsigned char *tag, size_t len);
void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);
void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx, unsigned int M, unsigned int L, void *key, block128_f block);
int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx, const unsigned char *nonce, size_t nlen, size_t mlen);
void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx, const unsigned char *aad, size_t alen);
int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx, const unsigned char *inp, unsigned char *out, size_t len);
int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx, const unsigned char *inp, unsigned char *out, size_t len);
int CRYPTO_ccm128_encrypt_ccm64(CCM128_CONTEXT *ctx, const unsigned char *inp, unsigned char *out, size_t len, ccm128_f stream);
int CRYPTO_ccm128_decrypt_ccm64(CCM128_CONTEXT *ctx, const unsigned char *inp, unsigned char *out, size_t len, ccm128_f stream);
size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
int CRYPTO_xts128_encrypt(const XTS128_CONTEXT *ctx, const unsigned char iv[16], const unsigned char *inp, unsigned char *out, size_t len, int enc);
size_t CRYPTO_128_wrap(void *key, const unsigned char *iv, unsigned char *out, const unsigned char *in, size_t inlen, block128_f block);
size_t CRYPTO_128_unwrap(void *key, const unsigned char *iv, unsigned char *out, const unsigned char *in, size_t inlen, block128_f block);
size_t CRYPTO_128_wrap_pad(void *key, const unsigned char *icv, unsigned char *out, const unsigned char *in, size_t inlen, block128_f block);
size_t CRYPTO_128_unwrap_pad(void *key, const unsigned char *icv, unsigned char *out, const unsigned char *in, size_t inlen, block128_f block);
OCB128_CONTEXT *CRYPTO_ocb128_new(void *keyenc, void *keydec, block128_f encrypt, block128_f decrypt, ocb128_f stream);
int CRYPTO_ocb128_init(OCB128_CONTEXT *ctx, void *keyenc, void *keydec, block128_f encrypt, block128_f decrypt, ocb128_f stream);
int CRYPTO_ocb128_copy_ctx(OCB128_CONTEXT *dest, OCB128_CONTEXT *src, void *keyenc, void *keydec);
int CRYPTO_ocb128_setiv(OCB128_CONTEXT *ctx, const unsigned char *iv, size_t len, size_t taglen);
int CRYPTO_ocb128_aad(OCB128_CONTEXT *ctx, const unsigned char *aad, size_t len);
int CRYPTO_ocb128_encrypt(OCB128_CONTEXT *ctx, const unsigned char *in, unsigned char *out, size_t len);
int CRYPTO_ocb128_decrypt(OCB128_CONTEXT *ctx, const unsigned char *in, unsigned char *out, size_t len);
int CRYPTO_ocb128_finish(OCB128_CONTEXT *ctx, const unsigned char *tag, size_t len);
int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len);
void CRYPTO_ocb128_cleanup(OCB128_CONTEXT *ctx);

/*----------------------------------------------------  PAILLIER  ----------------------------------------------------*/
PAILLIER *PAILLIER_new(void);
void PAILLIER_free(PAILLIER *key);
int PAILLIER_generate_key(PAILLIER *key, int bits);
int PAILLIER_check_key(PAILLIER *key);
int PAILLIER_encrypt(BIGNUM *out, const BIGNUM *in, PAILLIER *key);
int PAILLIER_decrypt(BIGNUM *out, const BIGNUM *in, PAILLIER *key);
int PAILLIER_ciphertext_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, PAILLIER *key);
int PAILLIER_ciphertext_scalar_mul(BIGNUM *r, const BIGNUM *scalar, const BIGNUM *a, PAILLIER *key);
int PAILLIER_up_ref(PAILLIER *key);
int ERR_load_PAILLIER_strings(void);
					   
/*----------------------------------------------------  RC  ----------------------------------------------------*/
void RC2_set_key(RC2_KEY *key, int len, const unsigned char *data, int bits);
void RC2_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     RC2_KEY *key, int enc);
void RC2_encrypt(unsigned long *data, RC2_KEY *key);
void RC2_decrypt(unsigned long *data, RC2_KEY *key);
void RC2_cbc_encrypt(const unsigned char *in, unsigned char *out, long length,
                     RC2_KEY *ks, unsigned char *iv, int enc);
void RC2_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, RC2_KEY *schedule, unsigned char *ivec,
                       int *num, int enc);
void RC2_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                       long length, RC2_KEY *schedule, unsigned char *ivec,
                       int *num);
const char *RC4_options(void);
void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
void RC4(RC4_KEY *key, size_t len, const unsigned char *indata,
         unsigned char *outdata);

/*		 
void RC5_32_set_key(RC5_32_KEY *key, int len, const unsigned char *data,
                    int rounds);
void RC5_32_ecb_encrypt(const unsigned char *in, unsigned char *out,
                        RC5_32_KEY *key, int enc);
void RC5_32_encrypt(unsigned long *data, RC5_32_KEY *key);
void RC5_32_decrypt(unsigned long *data, RC5_32_KEY *key);
void RC5_32_cbc_encrypt(const unsigned char *in, unsigned char *out,
                        long length, RC5_32_KEY *ks, unsigned char *iv,
                        int enc);
void RC5_32_cfb64_encrypt(const unsigned char *in, unsigned char *out,
                          long length, RC5_32_KEY *schedule,
                          unsigned char *ivec, int *num, int enc);
void RC5_32_ofb64_encrypt(const unsigned char *in, unsigned char *out,
                          long length, RC5_32_KEY *schedule,
                          unsigned char *ivec, int *num);
*/

/*----------------------------------------------------  RIPEMD  ----------------------------------------------------*/
int RIPEMD160_Init(RIPEMD160_CTX *c);
int RIPEMD160_Update(RIPEMD160_CTX *c, const void *data, size_t len);
int RIPEMD160_Final(unsigned char *md, RIPEMD160_CTX *c);
unsigned char *RIPEMD160(const unsigned char *d, size_t n, unsigned char *md);
void RIPEMD160_Transform(RIPEMD160_CTX *c, const unsigned char *b);			  
		
/*----------------------------------------------------  RSA  ----------------------------------------------------*/
RSA *RSA_new(void);
RSA *RSA_new_method(ENGINE *engine);
int RSA_bits(const RSA *rsa);
int RSA_size(const RSA *rsa);
int RSA_security_bits(const RSA *rsa);
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
int RSA_set0_factors(RSA *r, BIGNUM *p, BIGNUM *q);
int RSA_set0_crt_params(RSA *r,BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM *iqmp);
void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
void RSA_get0_factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
void RSA_get0_crt_params(const RSA *r, const BIGNUM **dmp1, const BIGNUM **dmq1, const BIGNUM **iqmp);
void RSA_clear_flags(RSA *r, int flags);
int RSA_test_flags(const RSA *r, int flags);
void RSA_set_flags(RSA *r, int flags);
ENGINE *RSA_get0_engine(const RSA *r);
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int RSA_X931_derive_ex(RSA *rsa, BIGNUM *p1, BIGNUM *p2, BIGNUM *q1, BIGNUM *q2, const BIGNUM *Xp1, const BIGNUM *Xp2, const BIGNUM *Xp, const BIGNUM *Xq1, const BIGNUM *Xq2, const BIGNUM *Xq, const BIGNUM *e, BN_GENCB *cb);
int RSA_X931_generate_key_ex(RSA *rsa, int bits, const BIGNUM *e, BN_GENCB *cb);
int RSA_check_key(const RSA *);
int RSA_check_key_ex(const RSA *, BN_GENCB *cb);
int RSA_public_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int RSA_private_encrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int RSA_public_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int RSA_private_decrypt(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
void RSA_free(RSA *r);
int RSA_up_ref(RSA *r);
int RSA_flags(const RSA *r);
void RSA_set_default_method(const RSA_METHOD *meth);
const RSA_METHOD *RSA_get_default_method(void);
const RSA_METHOD *RSA_get_method(const RSA *rsa);
int RSA_set_method(RSA *rsa, const RSA_METHOD *meth);
const RSA_METHOD *RSA_PKCS1_OpenSSL(void);
const RSA_METHOD *RSA_null_method(void);
int RSA_sign(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify(int type, const unsigned char *m, unsigned int m_length, const unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
int RSA_sign_ASN1_OCTET_STRING(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigret, unsigned int *siglen, RSA *rsa);
int RSA_verify_ASN1_OCTET_STRING(int type, const unsigned char *m, unsigned int m_length, unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
int RSA_blinding_on(RSA *rsa, BN_CTX *ctx);
void RSA_blinding_off(RSA *rsa);
BN_BLINDING *RSA_setup_blinding(RSA *rsa, BN_CTX *ctx);
int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen, const unsigned char *f, int fl);
int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len);
int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *f, int fl);
int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len);
int PKCS1_MGF1(unsigned char *mask, long len, const unsigned char *seed, long seedlen, const EVP_MD *dgst);
int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen, const unsigned char *f, int fl, const unsigned char *p, int pl);
int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len, const unsigned char *p, int pl);
int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen, const unsigned char *from, int flen, const unsigned char *param, int plen, const EVP_MD *md, const EVP_MD *mgf1md);
int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,  const unsigned char *from, int flen, int num, const unsigned char *param, int plen, const EVP_MD *md, const EVP_MD *mgf1md);
int RSA_padding_add_SSLv23(unsigned char *to, int tlen, const unsigned char *f, int fl);
int RSA_padding_check_SSLv23(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len);
int RSA_padding_add_none(unsigned char *to, int tlen, const unsigned char *f, int fl);
int RSA_padding_check_none(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len);
int RSA_padding_add_X931(unsigned char *to, int tlen, const unsigned char *f, int fl);
int RSA_padding_check_X931(unsigned char *to, int tlen, const unsigned char *f, int fl, int rsa_len);
int RSA_X931_hash_id(int nid);
int RSA_verify_PKCS1_PSS(RSA *rsa, const unsigned char *mHash, const EVP_MD *Hash, const unsigned char *EM, int sLen);
int RSA_padding_add_PKCS1_PSS(RSA *rsa, unsigned char *EM, const unsigned char *mHash, const EVP_MD *Hash, int sLen);
int RSA_verify_PKCS1_PSS_mgf1(RSA *rsa, const unsigned char *mHash, const EVP_MD *Hash, const EVP_MD *mgf1Hash, const unsigned char *EM, int sLen);
int RSA_padding_add_PKCS1_PSS_mgf1(RSA *rsa, unsigned char *EM, const unsigned char *mHash, const EVP_MD *Hash, const EVP_MD *mgf1Hash, int sLen);
int RSA_set_ex_data(RSA *r, int idx, void *arg);
void *RSA_get_ex_data(const RSA *r, int idx);
RSA *RSAPublicKey_dup(RSA *rsa);
RSA *RSAPrivateKey_dup(RSA *rsa);
RSA_METHOD *RSA_meth_new(const char *name, int flags);
void RSA_meth_free(RSA_METHOD *meth);
RSA_METHOD *RSA_meth_dup(const RSA_METHOD *meth);
const char *RSA_meth_get0_name(const RSA_METHOD *meth);
int RSA_meth_set1_name(RSA_METHOD *meth, const char *name);
int RSA_meth_get_flags(RSA_METHOD *meth);
int RSA_meth_set_flags(RSA_METHOD *meth, int flags);
int ERR_load_RSA_strings(void);

/*----------------------------------------------------  SEED  ----------------------------------------------------*/
void SEED_set_key(const unsigned char rawkey[SEED_KEY_LENGTH], SEED_KEY_SCHEDULE *ks);
void SEED_encrypt(const unsigned char s[SEED_BLOCK_SIZE], unsigned char d[SEED_BLOCK_SIZE], const SEED_KEY_SCHEDULE *ks);
void SEED_decrypt(const unsigned char s[SEED_BLOCK_SIZE], unsigned char d[SEED_BLOCK_SIZE], const SEED_KEY_SCHEDULE *ks);
void SEED_ecb_encrypt(const unsigned char *in, unsigned char *out, const SEED_KEY_SCHEDULE *ks, int enc);
void SEED_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const SEED_KEY_SCHEDULE *ks, unsigned char ivec[SEED_BLOCK_SIZE], int enc);
void SEED_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const SEED_KEY_SCHEDULE *ks, unsigned char ivec[SEED_BLOCK_SIZE], int *num, int enc);
void SEED_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const SEED_KEY_SCHEDULE *ks, unsigned char ivec[SEED_BLOCK_SIZE], int *num);
					 
/*----------------------------------------------------  SERPENT  ----------------------------------------------------*/	
void serpent_set_encrypt_key(serpent_key_t *key, const unsigned char *user_key);
void serpent_set_decrypt_key(serpent_key_t *key, const unsigned char *user_key);
void serpent_encrypt(const void *in, void *out, serpent_key_t *key);
void serpent_decrypt(const void *in, void *out, serpent_key_t *key);

/*----------------------------------------------------  SHA  ----------------------------------------------------*/
int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);
int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);


/*----------------------------------------------------  SM  ----------------------------------------------------*/
int SM2_compute_id_digest(const EVP_MD *md, const char *id, size_t idlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_compute_message_digest(const EVP_MD *id_md, const EVP_MD *msg_md, const unsigned char *msg, size_t msglen, const char *id, size_t idlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_sign_setup(EC_KEY *ec_key, BN_CTX *ctx, BIGNUM **a, BIGNUM **b);
ECDSA_SIG *SM2_do_sign_ex(const unsigned char *dgst, int dgstlen, const BIGNUM *a, const BIGNUM *b, EC_KEY *ec_key);
ECDSA_SIG *SM2_do_sign(const unsigned char *dgst, int dgst_len, EC_KEY *ec_key);
int SM2_do_verify(const unsigned char *dgst, int dgstlen, const ECDSA_SIG *sig, EC_KEY *ec_key);
int SM2_sign_ex(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, const BIGNUM *k, const BIGNUM *x, EC_KEY *ec_key);
int SM2_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);
int SM2_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char *sig, int siglen, EC_KEY *ec_key);
int i2o_SM2CiphertextValue(const EC_GROUP *group, const SM2CiphertextValue *cv, unsigned char **pout);
SM2CiphertextValue *o2i_SM2CiphertextValue(const EC_GROUP *group, const EVP_MD *md, SM2CiphertextValue **cv, const unsigned char **pin, long len);
SM2CiphertextValue *SM2_do_encrypt(const EVP_MD *md, const unsigned char *in, size_t inlen, EC_KEY *ec_key);
int SM2_do_decrypt(const EVP_MD *md, const SM2CiphertextValue *in, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_encrypt(int type, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2_decrypt(int type, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, EC_KEY *ec_key);
int SM2CiphertextValue_size(const EC_GROUP *group, int inlen);
int SM2_compute_share_key(unsigned char *out, size_t *outlen, const EC_POINT *peer_ephem, EC_KEY *ephem, const EC_POINT *peer_pk, const unsigned char *peer_z, size_t peer_zlen, const unsigned char *z, size_t zlen, EC_KEY *sk, int initiator);
int SM2_KAP_CTX_init(SM2_KAP_CTX *ctx, EC_KEY *ec_key, const char *id, size_t idlen, EC_KEY *remote_pubkey, const char *rid, size_t ridlen, int is_initiator, int do_checksum);
int SM2_KAP_prepare(SM2_KAP_CTX *ctx, unsigned char *ephem_point, size_t *ephem_point_len);
int SM2_KAP_compute_key(SM2_KAP_CTX *ctx, const unsigned char *remote_ephem_point, size_t remote_ephem_point_len, unsigned char *key, size_t keylen, unsigned char *checksum, size_t *checksumlen);
int SM2_KAP_final_check(SM2_KAP_CTX *ctx, const unsigned char *checksum, size_t checksumlen);
void SM2_KAP_CTX_cleanup(SM2_KAP_CTX *ctx);
const EC_KEY_METHOD *EC_KEY_GmSSL(void);
void EC_KEY_set_default_secg_method(void);
void EC_KEY_set_default_sm_method(void);
int EC_KEY_METHOD_type(const EC_KEY_METHOD *meth);
void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len);
void sm3_final(sm3_ctx_t *ctx, unsigned char digest[SM3_DIGEST_LENGTH]);
void sm3_compress(uint32_t digest[8], const unsigned char block[SM3_BLOCK_SIZE]);
void sm3(const unsigned char *data, size_t datalen, unsigned char digest[SM3_DIGEST_LENGTH]);
void sm3_hmac_init(sm3_hmac_ctx_t *ctx, const unsigned char *key, size_t key_len);
void sm3_hmac_update(sm3_hmac_ctx_t *ctx, const unsigned char *data, size_t data_len);
void sm3_hmac_final(sm3_hmac_ctx_t *ctx, unsigned char mac[SM3_HMAC_SIZE]);
void sm3_hmac(const unsigned char *data, size_t data_len, const unsigned char *key, size_t key_len, unsigned char mac[SM3_HMAC_SIZE]);
int SM9_setup_by_pairing_name(int nid, int hid, SM9PublicParameters **mpk, SM9MasterSecret **msk);
SM9PrivateKey *SM9_extract_private_key(SM9PublicParameters *mpk, SM9MasterSecret *msk, const char *id, size_t idlen);
SM9PublicKey *SM9_extract_public_key(SM9PublicParameters *mpk, const char *id, size_t idlen);
SM9PublicKey *SM9PrivateKey_get_public_key(SM9PublicParameters *mpk, SM9PrivateKey *sk);
int SM9PrivateKey_get_gmtls_public_key(SM9PublicParameters *mpk, SM9PrivateKey *sk, unsigned char pub_key[1024]);
int SM9PublicKey_get_gmtls_encoded(SM9PublicParameters *mpk, SM9PublicKey *pk, unsigned char encoded[1024]);
SM9Ciphertext *SM9_do_encrypt_ex(SM9PublicParameters *mpk, const SM9EncParameters *encparams, const unsigned char *in, size_t inlen, SM9PublicKey *pk);
SM9Ciphertext *SM9_do_encrypt(SM9PublicParameters *mpk, const SM9EncParameters *encparams, const unsigned char *in, size_t inlen, const char *id, size_t idlen);
int SM9_do_decrypt(SM9PublicParameters *mpk, const SM9EncParameters *encparams, const SM9Ciphertext *in, unsigned char *out, size_t *outlen, SM9PrivateKey *sk, const char *id, size_t idlen);
int SM9_encrypt_ex(SM9PublicParameters *mpk, const SM9EncParameters *encparams, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, SM9PublicKey *pk);
int SM9_encrypt(SM9PublicParameters *mpk, const SM9EncParameters *encparams, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, const char *id, size_t idlen);
int SM9_decrypt(SM9PublicParameters *mpk, const SM9EncParameters *encparams, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, SM9PrivateKey *sk, const char *id, size_t idlen);
int SM9_encrypt_with_recommended_ex(SM9PublicParameters *mpk, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, SM9PublicKey *pk);
int SM9_encrypt_with_recommended(SM9PublicParameters *mpk, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, const char *id, size_t idlen);
int SM9_decrypt_with_recommended(SM9PublicParameters *mpk, const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen, SM9PrivateKey *sk, const char *id, size_t idlen);
int SM9_signature_size(SM9PublicParameters *mpk);
SM9Signature *SM9_do_sign(SM9PublicParameters *mpk, const unsigned char *dgst, size_t dgstlen, SM9PrivateKey *sk);
int SM9_do_verify_ex(SM9PublicParameters *mpk, const unsigned char *dgst, size_t dgstlen, const SM9Signature *sig, SM9PublicKey *pk);
int SM9_do_verify(SM9PublicParameters *mpk, const unsigned char *dgst, size_t dgstlen, const SM9Signature *sig, const char *id, size_t idlen);
int SM9_sign(SM9PublicParameters *mpk, const unsigned char *dgst, size_t dgstlen, unsigned char *sig, size_t *siglen, SM9PrivateKey *sk);
int SM9_verify_ex(SM9PublicParameters *mpk, const unsigned char *dgst, size_t dgstlen, const unsigned char *sig, size_t siglen, SM9PublicKey *pk);
int SM9_verify(SM9PublicParameters *mpk, const unsigned char *dgst, size_t dgstlen, const unsigned char *sig, size_t siglen, const char *id, size_t idlen);
SM9PublicKey *SM9_generate_key_exchange(SM9PublicParameters *mpk, const char *peer_id, size_t peer_idlen, BIGNUM **r);
int SM9_compute_share_key(SM9PublicParameters *mpk, unsigned char *out, size_t *outlen, const char *peer_id, size_t peer_idlen, SM9PublicKey *peer_exch, const char *id, size_t idlen, SM9PublicKey *exch, SM9PrivateKey *sk, int initiator);
int ERR_load_SM9_strings(void);
void sms4_set_encrypt_key(sms4_key_t *key, const unsigned char *user_key);
void sms4_set_decrypt_key(sms4_key_t *key, const unsigned char *user_key);
void sms4_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key);
void sms4_encrypt_init(sms4_key_t *key);
void sms4_encrypt_8blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key);
void sms4_encrypt_16blocks(const unsigned char *in, unsigned char *out, const sms4_key_t *key);
void sms4_ecb_encrypt(const unsigned char *in, unsigned char *out, const sms4_key_t *key, int enc);
void sms4_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const sms4_key_t *key, unsigned char *iv, int enc);
void sms4_cfb128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const sms4_key_t *key, unsigned char *iv, int *num, int enc);
void sms4_ofb128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const sms4_key_t *key, unsigned char *iv, int *num);
void sms4_ctr128_encrypt(const unsigned char *in, unsigned char *out, size_t len, const sms4_key_t *key, unsigned char *iv, unsigned char ecount_buf[SMS4_BLOCK_SIZE], unsigned int *num);
int sms4_wrap_key(sms4_key_t *key, const unsigned char *iv, unsigned char *out, const unsigned char *in, unsigned int inlen);
int sms4_unwrap_key(sms4_key_t *key, const unsigned char *iv, unsigned char *out, const unsigned char *in, unsigned int inlen);

/*----------------------------------------------------  SPECK  ----------------------------------------------------*/
void speck_set_encrypt_key16(const uint16_t user[SPECK_KEY_LEN16], uint16_t key[SPECK_ROUNDS16]);
void speck_set_decrypt_key16(uint16_t const user[SPECK_KEY_LEN16], uint16_t key[SPECK_ROUNDS16]);
void speck_encrypt16(const uint16_t pt[2], uint16_t ct[2], const uint16_t K[SPECK_ROUNDS16]);
void speck_decrypt16(const uint16_t ct[2], uint16_t pt[2], const uint16_t K[SPECK_ROUNDS16]);
void speck_set_encrypt_key32(const uint32_t user[SPECK_KEY_LEN32], uint32_t key[SPECK_ROUNDS32]);
void speck_set_decrypt_key32(const uint32_t user[SPECK_KEY_LEN32], uint32_t key[SPECK_ROUNDS32]);
void speck_encrypt32(const uint32_t pt[2], uint32_t ct[2], const uint32_t K[SPECK_ROUNDS32]);
void speck_decrypt32(const uint32_t ct[2], uint32_t pt[2], const uint32_t K[SPECK_ROUNDS32]);
void speck_set_encrypt_key64(const uint64_t user[SPECK_KEY_LEN64], uint64_t key[SPECK_ROUNDS64]);
void speck_set_decrypt_key64(const uint64_t user[SPECK_KEY_LEN64], uint64_t key[SPECK_ROUNDS64]);
void speck_encrypt64(const uint64_t pt[2], uint64_t ct[2], const uint64_t K[SPECK_ROUNDS64]);
void speck_decrypt64(const uint64_t ct[2], uint64_t pt[2], const uint64_t K[SPECK_ROUNDS64]);

/*----------------------------------------------------  SRP  ----------------------------------------------------*/
SRP_VBASE *SRP_VBASE_new(char *seed_key);
void SRP_VBASE_free(SRP_VBASE *vb);
int SRP_VBASE_init(SRP_VBASE *vb, char *verifier_file);
SRP_user_pwd *SRP_VBASE_get1_by_user(SRP_VBASE *vb, char *username);
char *SRP_create_verifier(const char *user, const char *pass, char **salt, char **verifier, const char *N, const char *g);
int SRP_create_verifier_BN(const char *user, const char *pass, BIGNUM **salt, BIGNUM **verifier, const BIGNUM *N, const BIGNUM *g);
char *SRP_check_known_gN_param(const BIGNUM *g, const BIGNUM *N);
SRP_gN *SRP_get_default_gN(const char *id);
BIGNUM *SRP_Calc_server_key(const BIGNUM *A, const BIGNUM *v, const BIGNUM *u, const BIGNUM *b, const BIGNUM *N);
BIGNUM *SRP_Calc_B(const BIGNUM *b, const BIGNUM *N, const BIGNUM *g, const BIGNUM *v);
int SRP_Verify_A_mod_N(const BIGNUM *A, const BIGNUM *N);
BIGNUM *SRP_Calc_u(const BIGNUM *A, const BIGNUM *B, const BIGNUM *N);
BIGNUM *SRP_Calc_x(const BIGNUM *s, const char *user, const char *pass);
BIGNUM *SRP_Calc_A(const BIGNUM *a, const BIGNUM *N, const BIGNUM *g);
BIGNUM *SRP_Calc_client_key(const BIGNUM *N, const BIGNUM *B, const BIGNUM *g, const BIGNUM *x, const BIGNUM *a, const BIGNUM *u);
int SRP_Verify_B_mod_N(const BIGNUM *B, const BIGNUM *N);

/*----------------------------------------------------  WHIRLPOOL  ----------------------------------------------------*/
int WHIRLPOOL_Init(WHIRLPOOL_CTX *c);
int WHIRLPOOL_Update(WHIRLPOOL_CTX *c, const void *inp, size_t bytes);
void WHIRLPOOL_BitUpdate(WHIRLPOOL_CTX *c, const void *inp, size_t bits);
int WHIRLPOOL_Final(unsigned char *md, WHIRLPOOL_CTX *c);
unsigned char *WHIRLPOOL(const void *inp, size_t bytes, unsigned char *md);

/*----------------------------------------------------  ZUC  ----------------------------------------------------*/
void ZUC_set_key(ZUC_KEY *key, const unsigned char *user_key, const unsigned char *iv);
void ZUC_generate_keystream(ZUC_KEY *key, size_t nwords, uint32_t *words);
uint32_t ZUC_generate_keyword(ZUC_KEY *key);
void ZUC_128eea3_set_key(ZUC_128EEA3 *ctx, const unsigned char user_key[16], ZUC_UINT32 count, ZUC_UINT5 bearer, ZUC_UINT1 direction);
void ZUC_128eea3_encrypt(ZUC_128EEA3 *ctx, size_t len, const unsigned char *in, unsigned char *out);
void ZUC_128eea3(const unsigned char key[ZUC_KEY_LENGTH], ZUC_UINT32 count, ZUC_UINT5 bearer, ZUC_UINT1 direction, size_t len, const unsigned char *in, unsigned char *out);
void ZUC_128eia3_set_key(ZUC_128EIA3 *ctx, const unsigned char *user_key, ZUC_UINT32 count, ZUC_UINT5 bearer, ZUC_UINT1 direction);
void ZUC_128eia3_update(ZUC_128EIA3 *ctx, const unsigned char *data, size_t datalen);
void ZUC_128eia3_final(ZUC_128EIA3 *ctx, uint32_t *mac);
void ZUC_128eia3(const unsigned char key[ZUC_KEY_LENGTH], ZUC_UINT32 count, ZUC_UINT5 bearer, ZUC_UINT1 direction, const unsigned char *data, size_t dlen, uint32_t *mac);


