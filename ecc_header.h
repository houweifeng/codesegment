#define BN_ULONG        unsigned long
#define EC_FLAGS_DEFAULT_OCT    0x1
#define EC_FLAGS_CUSTOM_CURVE   0x2
#define EC_FLAGS_NO_SIGN        0x4


struct EC_GROUP;
struct BN_CTX;
struct EC_POINT;
struct BIGNUM;
struct EC_KEY;
struct EC_METHOD;
struct EC_KEY_METHOD;
struct BN_MONT_CTX;
struct CRYPTO_EX_DATA;
struct ECDSA_SIG;
struct ECIES_CIPHERTEXT_VALUE;
struct CRYPTO_EX_DATA;
struct BN_STACK;

struct bignum_st {
    BN_ULONG *d;                /* Pointer to an array of 'BN_BITS2' bit
                                 * chunks. */
    int top;                    /* Index of last used d +1. */
    /* The next are internal book keeping for bn_expand. */
    int dmax;                   /* Size of the d array. */
    int neg;                    /* one if the number is negative */
    int flags;
};

typedef enum {
        /** the point is encoded as z||x, where the octet z specifies
         *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_COMPRESSED = 2,
        /** the point is encoded as z||x||y, where z is the octet 0x04  */
    POINT_CONVERSION_UNCOMPRESSED = 4,
        /** the point is encoded as z||x||y, where the octet z specifies
         *  which solution of the quadratic equation y is  */
    POINT_CONVERSION_HYBRID = 6
} point_conversion_form_t;


struct ec_method_st {
    int flags;
    int field_type;             /* a NID */
    int (*group_init) (EC_GROUP *);
    void (*group_finish) (EC_GROUP *);
    void (*group_clear_finish) (EC_GROUP *);
    int (*group_copy) (EC_GROUP *, const EC_GROUP *);
    int (*group_set_curve) (EC_GROUP *, const BIGNUM *p, const BIGNUM *a,
                            const BIGNUM *b, BN_CTX *);
    int (*group_get_curve) (const EC_GROUP *, BIGNUM *p, BIGNUM *a, BIGNUM *b,
                            BN_CTX *);
    int (*group_get_degree) (const EC_GROUP *);
    int (*group_order_bits) (const EC_GROUP *);
    int (*group_check_discriminant) (const EC_GROUP *, BN_CTX *);
    int (*point_init) (EC_POINT *);
    void (*point_finish) (EC_POINT *);
    void (*point_clear_finish) (EC_POINT *);
    int (*point_copy) (EC_POINT *, const EC_POINT *);

    int (*point_set_to_infinity) (const EC_GROUP *, EC_POINT *);
    int (*point_set_Jprojective_coordinates_GFp) (const EC_GROUP *,
                                                  EC_POINT *, const BIGNUM *x,
                                                  const BIGNUM *y,
                                                  const BIGNUM *z, BN_CTX *);
    int (*point_get_Jprojective_coordinates_GFp) (const EC_GROUP *,
                                                  const EC_POINT *, BIGNUM *x,
                                                  BIGNUM *y, BIGNUM *z,
                                                  BN_CTX *);
    int (*point_set_affine_coordinates) (const EC_GROUP *, EC_POINT *,
                                         const BIGNUM *x, const BIGNUM *y,
                                         BN_CTX *);
    int (*point_get_affine_coordinates) (const EC_GROUP *, const EC_POINT *,
                                         BIGNUM *x, BIGNUM *y, BN_CTX *);
    int (*point_set_compressed_coordinates) (const EC_GROUP *, EC_POINT *,
                                             const BIGNUM *x, int y_bit,
                                             BN_CTX *);
    /* used by EC_POINT_point2oct, EC_POINT_oct2point: */
    size_t (*point2oct) (const EC_GROUP *, const EC_POINT *,
                         point_conversion_form_t form, unsigned char *buf,
                         size_t len, BN_CTX *);
    int (*oct2point) (const EC_GROUP *, EC_POINT *, const unsigned char *buf,
                      size_t len, BN_CTX *);
    /* used by EC_POINT_add, EC_POINT_dbl, ECP_POINT_invert: */
    int (*add) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
                const EC_POINT *b, BN_CTX *);
    int (*dbl) (const EC_GROUP *, EC_POINT *r, const EC_POINT *a, BN_CTX *);
    int (*invert) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    /*
     * used by EC_POINT_is_at_infinity, EC_POINT_is_on_curve, EC_POINT_cmp:
     */
    int (*is_at_infinity) (const EC_GROUP *, const EC_POINT *);
    int (*is_on_curve) (const EC_GROUP *, const EC_POINT *, BN_CTX *);
    int (*point_cmp) (const EC_GROUP *, const EC_POINT *a, const EC_POINT *b,
                      BN_CTX *);
    /* used by EC_POINT_make_affine, EC_POINTs_make_affine: */
    int (*make_affine) (const EC_GROUP *, EC_POINT *, BN_CTX *);
    int (*points_make_affine) (const EC_GROUP *, size_t num, EC_POINT *[],
                               BN_CTX *);
    int (*mul) (const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *);
    int (*precompute_mult) (EC_GROUP *group, BN_CTX *);
    int (*have_precompute_mult) (const EC_GROUP *group);
    int (*field_mul) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    int (*field_sqr) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a, BN_CTX *);
    int (*field_div) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                      const BIGNUM *b, BN_CTX *);
    /* e.g. to Montgomery */
    int (*field_encode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    /* e.g. from Montgomery */
    int (*field_decode) (const EC_GROUP *, BIGNUM *r, const BIGNUM *a,
                         BN_CTX *);
    int (*field_set_to_one) (const EC_GROUP *, BIGNUM *r, BN_CTX *);
    /* private key operations */
    size_t (*priv2oct)(const EC_KEY *eckey, unsigned char *buf, size_t len);
    int (*oct2priv)(EC_KEY *eckey, const unsigned char *buf, size_t len);
    int (*set_private)(EC_KEY *eckey, const BIGNUM *priv_key);
    int (*keygen)(EC_KEY *eckey);
    int (*keycheck)(const EC_KEY *eckey);
    int (*keygenpub)(EC_KEY *eckey);
    int (*keycopy)(EC_KEY *dst, const EC_KEY *src);
    void (*keyfinish)(EC_KEY *eckey);
    /* custom ECDH operation */
    int (*ecdh_compute_key)(unsigned char **pout, size_t *poutlen,
                            const EC_POINT *pub_key, const EC_KEY *ecdh);
};

/*
 * Types and functions to manipulate pre-computed values.
 */
typedef struct nistp224_pre_comp_st NISTP224_PRE_COMP;
typedef struct nistp256_pre_comp_st NISTP256_PRE_COMP;
typedef struct nistp521_pre_comp_st NISTP521_PRE_COMP;
typedef struct nistz256_pre_comp_st NISTZ256_PRE_COMP;
typedef struct ec_pre_comp_st EC_PRE_COMP;

struct ec_group_st {
    const EC_METHOD *meth;
    EC_POINT *generator;        /* optional */
    BIGNUM *order, *cofactor;
    int curve_name;             /* optional NID for named curve */
    int asn1_flag;              /* flag to control the asn1 encoding */
    point_conversion_form_t asn1_form;
    unsigned char *seed;        /* optional seed for parameters (appears in
                                 * ASN1) */
    size_t seed_len;
    BIGNUM *field;
    int poly[6];
    BIGNUM *a, *b;
    /* enable optimized point arithmetics for special case */
    int a_is_minus3;
    /* method-specific (e.g., Montgomery structure) */
    void *field_data1;
    /* method-specific */
    void *field_data2;
    /* method-specific */
    int (*field_mod_func) (BIGNUM *, const BIGNUM *, const BIGNUM *,
                           BN_CTX *);
    /* data for ECDSA inverse */
    BN_MONT_CTX *mont_data;
    enum {
        PCT_none,
        PCT_nistp224, PCT_nistp256, PCT_nistp521, PCT_nistz256,
        PCT_ec
    } pre_comp_type;
    union {
        NISTP224_PRE_COMP *nistp224;
        NISTP256_PRE_COMP *nistp256;
        NISTP521_PRE_COMP *nistp521;
        NISTZ256_PRE_COMP *nistz256;
        EC_PRE_COMP *ec;
    } pre_comp;
};

#define SETPRECOMP(g, type, pre) \
    g->pre_comp_type = PCT_##type, g->pre_comp.type = pre
#define HAVEPRECOMP(g, type) \
    g->pre_comp_type == PCT_##type && g->pre_comp.type != NULL

struct ec_key_st {
    const EC_KEY_METHOD *meth;
    void *engine;
    int version;
    EC_GROUP *group;
    EC_POINT *pub_key;
    BIGNUM *priv_key;
    unsigned int enc_flag;
    point_conversion_form_t conv_form;
    int references;
    int flags;
    CRYPTO_EX_DATA ex_data;
    void* lock;
};

struct ec_point_st {
    const EC_METHOD *meth;
    BIGNUM *X;
    BIGNUM *Y;
    BIGNUM *Z;                  /* Jacobian projective coordinates: * (X, Y,
                                 * Z) represents (X/Z^2, Y/Z^3) if Z != 0 */
    int Z_is_one;               /* enable optimized point arithmetics for
                                 * special case */
};

/* EC_METHOD definitions */

struct ec_key_method_st {
    const char *name;
    int32_t flags;
    int (*init)(EC_KEY *key);
    void (*finish)(EC_KEY *key);
    int (*copy)(EC_KEY *dest, const EC_KEY *src);
    int (*set_group)(EC_KEY *key, const EC_GROUP *grp);
    int (*set_private)(EC_KEY *key, const BIGNUM *priv_key);
    int (*set_public)(EC_KEY *key, const EC_POINT *pub_key);
    int (*keygen)(EC_KEY *key);
    int (*compute_key)(unsigned char **pout, size_t *poutlen,
                       const EC_POINT *pub_key, const EC_KEY *ecdh);
    int (*sign)(int type, const unsigned char *dgst, int dlen, unsigned char
                *sig, unsigned int *siglen, const BIGNUM *kinv,
                const BIGNUM *r, EC_KEY *eckey);
    int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                      BIGNUM **rp);
    ECDSA_SIG *(*sign_sig)(const unsigned char *dgst, int dgst_len,
                           const BIGNUM *in_kinv, const BIGNUM *in_r,
                           EC_KEY *eckey);

    int (*verify)(int type, const unsigned char *dgst, int dgst_len,
                  const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
    int (*verify_sig)(const unsigned char *dgst, int dgst_len,
                      const ECDSA_SIG *sig, EC_KEY *eckey);
    int (*encrypt)(int type, const unsigned char *in, size_t inlen,
                   unsigned char *out, size_t *outlen, EC_KEY *ec_key);
    ECIES_CIPHERTEXT_VALUE *(*do_encrypt)(int type, const unsigned char *in,
                                          size_t inlen, EC_KEY *ec_key);
    int (*decrypt)(int type, const unsigned char *in, size_t inlen,
                   unsigned char *out, size_t *outlen, EC_KEY *ec_key);
    int (*do_decrypt)(int type, const ECIES_CIPHERTEXT_VALUE *in,
                      unsigned char *out, size_t *outlen, EC_KEY *ec_key);
};

#define EC_KEY_METHOD_DYNAMIC   1



#define BN_CTX_POOL_SIZE        16
typedef struct bignum_pool_item {
    /* The bignum values */
    BIGNUM vals[BN_CTX_POOL_SIZE];
    /* Linked-list admin */
    struct bignum_pool_item *prev, *next;
} BN_POOL_ITEM;

/* A linked-list of bignums grouped in bundles */
typedef struct bignum_pool {
    /* Linked-list admin */
    BN_POOL_ITEM *head, *current, *tail;
    /* Stack depth and allocation size */
    unsigned used, size;
} BN_POOL;
								
/* The opaque BN_CTX type */
struct bignum_ctx {
    /* The bignum bundles */
    BN_POOL pool;
    /* The "stack frames", if you will */
    BN_STACK stack;
    /* The number of bignums currently assigned */
    unsigned int used;
    /* Depth of stack overflow */
    int err_stack;
    /* Block "gets" until an "end" (compatibility behaviour) */
    int too_many;
    /* Flags. */
    int flags;
};

struct ec_point_st {
    const EC_METHOD *meth;
    /*
     * All members except 'meth' are handled by the method functions, even if
     * they appear generic
     */
    BIGNUM *X;
    BIGNUM *Y;
    BIGNUM *Z;                  /* Jacobian projective coordinates: * (X, Y,
                                 * Z) represents (X/Z^2, Y/Z^3) if Z != 0 */
    int Z_is_one;               /* enable optimized point arithmetics for
                                 * special case */
};

struct bn_mont_ctx_st {
    int ri;                     /* number of bits in R */
    BIGNUM RR;                  /* used to convert to montgomery form */
    BIGNUM N;                   /* The modulus */
    BIGNUM Ni;                  /* R*(1/R mod N) - N*Ni = 1 (Ni is only
                                 * stored for bignum algorithm) */
    unsigned long n0[2];             /* least significant word(s) of Ni; (type
                                 * changed with 0.9.9, was "BN_ULONG n0;"
                                 * before) */
    int flags;
};

struct ec_key_method_st {
    const char *name;
    int32_t flags;
    int (*init)(EC_KEY *key);
    void (*finish)(EC_KEY *key);
    int (*copy)(EC_KEY *dest, const EC_KEY *src);
    int (*set_group)(EC_KEY *key, const EC_GROUP *grp);
    int (*set_private)(EC_KEY *key, const BIGNUM *priv_key);
    int (*set_public)(EC_KEY *key, const EC_POINT *pub_key);
    int (*keygen)(EC_KEY *key);
    int (*compute_key)(unsigned char **pout, size_t *poutlen,
                       const EC_POINT *pub_key, const EC_KEY *ecdh);
    int (*sign)(int type, const unsigned char *dgst, int dlen, unsigned char
                *sig, unsigned int *siglen, const BIGNUM *kinv,
                const BIGNUM *r, EC_KEY *eckey);
    int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp,
                      BIGNUM **rp);
    ECDSA_SIG *(*sign_sig)(const unsigned char *dgst, int dgst_len,
                           const BIGNUM *in_kinv, const BIGNUM *in_r,
                           EC_KEY *eckey);

    int (*verify)(int type, const unsigned char *dgst, int dgst_len,
                  const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);
    int (*verify_sig)(const unsigned char *dgst, int dgst_len,
                      const ECDSA_SIG *sig, EC_KEY *eckey);
    int (*encrypt)(int type, const unsigned char *in, size_t inlen,
                   unsigned char *out, size_t *outlen, EC_KEY *ec_key);
    ECIES_CIPHERTEXT_VALUE *(*do_encrypt)(int type, const unsigned char *in,
                                          size_t inlen, EC_KEY *ec_key);
    int (*decrypt)(int type, const unsigned char *in, size_t inlen,
                   unsigned char *out, size_t *outlen, EC_KEY *ec_key);
    int (*do_decrypt)(int type, const ECIES_CIPHERTEXT_VALUE *in,
                      unsigned char *out, size_t *outlen, EC_KEY *ec_key);
};

struct crypto_ex_data_st {
    void *sk;
};

struct ECDSA_SIG_st {
    BIGNUM *r;
    BIGNUM *s;
};


struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;
    /*
     * The value of the following field depends on the type being held.  It
     * is mostly being used for BIT_STRING so if the input data has a
     * non-zero 'unused bits' value, it will be handled correctly
     */
    long flags;
};
typedef struct asn1_string_st ASN1_OCTET_STRING;
struct ecies_ciphertext_value_st {
	ASN1_OCTET_STRING *ephem_point;
	ASN1_OCTET_STRING *ciphertext;
	ASN1_OCTET_STRING *mactag;
};

typedef struct bignum_ctx_stack {
    /* Array of indexes into the bignum stack */
    unsigned int *indexes;
    /* Number of stack frames, and the size of the allocated array */
    unsigned int depth, size;
} BN_STACK;


typedef struct {
	BIGNUM *x;
	BIGNUM *y;
	EC_POINT *ec_point;
} xy_ecpoint;

typedef struct {
	BN_CTX *ctx;
	BIGNUM *p;
	BIGNUM *a;
	BIGNUM *b;
	BIGNUM *n;
	xy_ecpoint *G;
	EC_GROUP *group;
	int type;
	int point_bit_length;
	int point_byte_length;

	EC_GROUP *(*EC_GROUP_new_curve)(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
	int (*EC_POINT_set_affine_coordinates)(const EC_GROUP *group, EC_POINT *p,
		const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
	int (*EC_POINT_get_affine_coordinates)(const EC_GROUP *group,
		const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);

} ec_param;

typedef struct {
	BIGNUM *x;
	BIGNUM *y;
	EC_POINT *ec_point;
} xy_ecpoint;

typedef bignum_st BIGNUM;
typedef ec_method_st EC_METHOD;
typedef ec_group_st EC_GROUP;
typedef struct bignum_ctx BN_CTX;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
typedef struct bn_mont_ctx_st BN_MONT_CTX;
typedef struct ec_key_method_st EC_KEY_METHOD;
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
typedef struct ECDSA_SIG_st ECDSA_SIG;
typedef struct ecies_ciphertext_value_st ECIES_CIPHERTEXT_VALUE;
