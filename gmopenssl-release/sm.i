%constant int SM2_MAX_ID_BITS = 65535;
%constant int SM2_DEFAULT_ID_DIGEST_LENGTH = SM3_DIGEST_LENGTH;
%constant int SM2_MIN_PLAINTEXT_LENGTH = 0;
%constant int SM2_MAX_PLAINTEXT_LENGTH = 1024;
%constant int SM2_F_I2O_SM2CIPHERTEXTVALUE          = 107;
%constant int SM2_F_O2I_SM2CIPHERTEXTVALUE          = 108;
%constant int SM2_F_SM2_DECRYPT                     = 100;
%constant int SM2_F_SM2_DO_DECRYPT                  = 101;
%constant int SM2_F_SM2_DO_ENCRYPT                  = 102;
%constant int SM2_F_SM2_DO_SIGN                     = 104;
%constant int SM2_F_SM2_DO_VERIFY                   = 105;
%constant int SM2_F_SM2_ENCRYPT                     = 103;
%constant int SM2_F_SM2_SIGN_SETUP                  = 106;
%constant int SM2_R_BAD_SIGNATURE                   = 110;
%constant int SM2_R_BUFFER_TOO_SMALL                = 100;
%constant int SM2_R_DECRYPT_FAILURE                 = 101;
%constant int SM2_R_ENCRYPT_FAILURE                 = 102;
%constant int SM2_R_INVALID_CIPHERTEXT              = 103;
%constant int SM2_R_INVALID_DIGEST_ALGOR            = 104;
%constant int SM2_R_INVALID_EC_KEY                  = 105;
%constant int SM2_R_INVALID_INPUT_LENGTH            = 106;
%constant int SM2_R_INVALID_PLAINTEXT_LENGTH        = 107;
%constant int SM2_R_INVALID_PUBLIC_KEY              = 108;
%constant int SM2_R_KDF_FAILURE                     = 109;
%constant int SM2_R_MISSING_PARAMETERS              = 111;
%constant int SM2_R_NEED_NEW_SETUP_VALUES           = 112;
%constant int SM2_R_RANDOM_NUMBER_GENERATION_FAILED = 113;
%constant int SM3_DIGEST_LENGTH	= 32;
%constant int SM3_BLOCK_SIZE = 64;
%constant int SM3_CBLOCK = SM3_BLOCK_SIZE;
%constant int SM3_HMAC_SIZE	= SM3_DIGEST_LENGTH;


%inline %{


#define HASH_BYTE_LENGTH 32
#define HASH_BIT_LENGTH 256
#define TYPE_GFp 0
#define TYPE_GF2m 1
#define MAX_POINT_BYTE_LENGTH 64  //点中x, y的最大字节长度

#define ORDER_A_B 0
#define ORDER_B_A 1

#define DEFINE_SHOW_BIGNUM(x) \
	printf(#x":\n"); \
	show_bignum(x, ecp->point_byte_length);\
	printf("\n")

#define DEFINE_SHOW_STRING(x, length1) \
	printf(#x":\n"); \
	show_string(x, length1);\
	printf("\n")

#define BUFFER_APPEND_BIGNUM(buffer1, pos1, point_byte_length, x) \
	BN_bn2bin(x, &buffer1[pos1 + point_byte_length - BN_num_bytes(x)]); \
	pos1 = pos1 + point_byte_length

#define BUFFER_APPEND_STRING(buffer1, pos1, length1, x) \
	memcpy(&buffer1[pos1], x, length1); \
	pos1 = pos1 + length1

typedef struct
{
	BYTE buffer[1024];
	int position;
	BYTE hash[HASH_BYTE_LENGTH];
} sm2_hash;

typedef struct
{
	BIGNUM *x;
	BIGNUM *y;
	EC_POINT *ec_point;
} xy_ecpoint;

/************************************************************************/
/* 定义椭圆曲线参数信息                                                 */
/************************************************************************/
typedef struct
{
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
	int(*EC_POINT_set_affine_coordinates)(const EC_GROUP *group, EC_POINT *p,
	                                      const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
	int(*EC_POINT_get_affine_coordinates)(const EC_GROUP *group,
	                                      const EC_POINT *p, BIGNUM *x, BIGNUM *y, BN_CTX *ctx);

} ec_param;

typedef struct
{
	BIGNUM *d;
	xy_ecpoint *P;
} sm2_ec_key;

struct pt
{
	BYTE x[MAX_POINT_BYTE_LENGTH];
	BYTE y[MAX_POINT_BYTE_LENGTH];
};

typedef struct
{
    BYTE *message;
    int message_byte_length;
    BYTE *ID;
    int ENTL;
    BYTE k[MAX_POINT_BYTE_LENGTH];  //«©√˚÷–≤˙…˙ÀÊª˙ ˝
    BYTE private_key[MAX_POINT_BYTE_LENGTH];
    struct pt public_key;
    BYTE Z[HASH_BYTE_LENGTH];
    BYTE r[MAX_POINT_BYTE_LENGTH];
    BYTE s[MAX_POINT_BYTE_LENGTH];
    BYTE R[MAX_POINT_BYTE_LENGTH];
} sm2_sign_st;

typedef struct
{
    BYTE *message;
    int message_byte_length;
    //BYTE *encrypt;
    BYTE *decrypt;
    int klen_bit;
    
    BYTE k[MAX_POINT_BYTE_LENGTH];  //ÀÊª˙ ˝
    BYTE private_key[MAX_POINT_BYTE_LENGTH];
    struct pt public_key;
    
    BYTE C[1024];    // C_1 || C_2 || C_3
    BYTE C_1[1024];
    BYTE C_2[1024];  //º”√‹∫Ûµƒœ˚œ¢
    BYTE C_3[1024];
    
} message_st;


typedef struct 
{
	BYTE *ID;
	int ENTL;

	int klen_bit;

	BYTE r[MAX_POINT_BYTE_LENGTH];  //随机数
	BYTE private_key[MAX_POINT_BYTE_LENGTH];
	struct pt public_key;
	BYTE K[256];  //共享密钥
	BYTE Z[HASH_BYTE_LENGTH];  //用户hash值
	struct pt R;  //r计算后得到的曲线点

	sm2_hash hash_tmp_data;  //保存计算hash的缓冲数据
} sm2_dh_st;

typedef struct 
{
	BYTE S_1[HASH_BYTE_LENGTH];  //hash
	BYTE S_A[HASH_BYTE_LENGTH];  //hash
	BYTE S_2[HASH_BYTE_LENGTH];  //hash
	BYTE S_B[HASH_BYTE_LENGTH];  //hash
} sm2_dh_hash_st;


xy_ecpoint *xy_ecpoint_new(ec_param *ecp)
{
	xy_ecpoint *xyp;
	xyp = (xy_ecpoint *)OPENSSL_malloc(sizeof(xy_ecpoint));
	xyp->x = BN_new();
	xyp->y = BN_new();
	xyp->ec_point = EC_POINT_new(ecp->group);
	return xyp;
}
void xy_ecpoint_free(xy_ecpoint *xyp)
{
	if (xyp)
	{
		BN_free(xyp->x);
		xyp->x = NULL;
		BN_free(xyp->y);
		xyp->y = NULL;
		EC_POINT_free(xyp->ec_point);
		xyp->ec_point = NULL;
		OPENSSL_free(xyp);
	}
}

int xy_ecpoint_mul_bignum(xy_ecpoint *result, xy_ecpoint *a, BIGNUM *number
                          , ec_param *ecp)
{
	EC_POINT_mul(ecp->group, result->ec_point, NULL, a->ec_point, number, ecp->ctx);
	ecp->EC_POINT_get_affine_coordinates(ecp->group
	                                     , (result)->ec_point
	                                     , (result)->x
	                                     , (result)->y
	                                     , ecp->ctx);

	return 1;
}

int xy_ecpoint_add_xy_ecpoint(xy_ecpoint *result, xy_ecpoint *a, xy_ecpoint *b
                              , ec_param *ecp)
{
	EC_POINT_add(ecp->group, (result)->ec_point, a->ec_point, b->ec_point, ecp->ctx);
	ecp->EC_POINT_get_affine_coordinates(ecp->group, (result)->ec_point
	                                     , (result)->x, (result)->y
	                                     , ecp->ctx);
	return 1;
}

int xy_ecpoint_init_xy(xy_ecpoint *result, BIGNUM *x, BIGNUM *y
                       , ec_param *ecp)
{
	//设置ec_point
	ecp->EC_POINT_set_affine_coordinates(ecp->group, (result)->ec_point
	                                     , x, y
	                                     , ecp->ctx);

	//获取x, y
	ecp->EC_POINT_get_affine_coordinates(ecp->group, (result)->ec_point
	                                     , (result)->x, (result)->y
	                                     , ecp->ctx);
	return 1;
}
int xy_ecpoint_init_ec_point(xy_ecpoint *result, EC_POINT *ec_point
                             , ec_param *ecp)
{
	//获取x, y
	ecp->EC_POINT_get_affine_coordinates(ecp->group, ec_point
	                                     , (result)->x, (result)->y
	                                     , ecp->ctx);

	//设置ec_point
	ecp->EC_POINT_set_affine_coordinates(ecp->group, (result)->ec_point
	                                     , (result)->x, (result)->y
	                                     , ecp->ctx);
	return 1;
}


/*
 *初始化椭圆曲线
 *参数PAB确定的是一条椭圆曲线的参数
 *y2=x3+ax+b（参数的曲线方式）
 *p是素数，一般指的是F(p)中的元素的个数
 *a，b 确定一条椭圆曲线
 *
 *n 基点G的阶(一般要求为素数)
 */
ec_param * ec_param_new(void)
{
	ec_param *ecp;
	ecp = (ec_param *)OPENSSL_malloc(sizeof(ec_param));
	/*申请一个大数上下文环境*/
	ecp->ctx = BN_CTX_new();
	ecp->p = BN_new();
	ecp->a = BN_new();
	ecp->b = BN_new();
	ecp->n = BN_new();
	return ecp;
}
//************************************
// Method:    ec_param_free
// FullName:  ec_param_free
// Access:    public
// Returns:   void
// Qualifier: 释放空间
// Parameter: ec_param * ecp
//************************************
void ec_param_free(ec_param *ecp)
{
	if (ecp)
	{
		BN_free(ecp->p);
		ecp->p = NULL;
		BN_free(ecp->a);
		ecp->a = NULL;
		BN_free(ecp->b);
		ecp->b = NULL;
		BN_free(ecp->n);
		ecp->n = NULL;
		if (ecp->G)
		{
			xy_ecpoint_free(ecp->G);
			ecp->G = NULL;
		}
		if (ecp->group)
		{
			EC_GROUP_free(ecp->group);
			ecp->group = NULL;
		}
		BN_CTX_free(ecp->ctx);
		ecp->ctx = NULL;
		OPENSSL_free(ecp);
	}
}


//************************************
// Method:    ec_param_init
// FullName:  ec_param_init
// Access:    public
// Returns:   int
// Qualifier:初始化椭圆曲线的参数
// Parameter: ec_param * ecp 椭圆曲线参数结构
// Parameter: char * * string_value 要初始化的值
// Parameter: int type 椭圆曲线的类型（共两种GFP金额GF2M）
// Parameter: int point_bit_length 点坐标的长度
//************************************
int ec_param_init(ec_param *ecp, char **string_value, int type, int point_bit_length)
{
	ecp->type = type;
	if (TYPE_GFp == ecp->type)
	{
		ecp->EC_GROUP_new_curve = EC_GROUP_new_curve_GFp;
		ecp->EC_POINT_set_affine_coordinates = EC_POINT_set_affine_coordinates_GFp;
		ecp->EC_POINT_get_affine_coordinates = EC_POINT_get_affine_coordinates_GFp;
	}
	else if (TYPE_GF2m == ecp->type)
	{
		ecp->EC_GROUP_new_curve = EC_GROUP_new_curve_GF2m;
		ecp->EC_POINT_set_affine_coordinates = EC_POINT_set_affine_coordinates_GF2m;
		ecp->EC_POINT_get_affine_coordinates = EC_POINT_get_affine_coordinates_GF2m;
	}

	/*hex转换成big number*/
	BN_hex2bn(&ecp->p, string_value[0]);
	BN_hex2bn(&ecp->a, string_value[1]);
	BN_hex2bn(&ecp->b, string_value[2]);
	BN_hex2bn(&ecp->n, string_value[5]);

	/*密钥参数group，这个群的概念就是定义曲线上离散的点和相对应的操作*/
	ecp->group = ecp->EC_GROUP_new_curve(ecp->p, ecp->a
	                                     , ecp->b, ecp->ctx);
	/*椭圆参数的基点G*/
	ecp->G = xy_ecpoint_new(ecp);
	BN_hex2bn(&ecp->G->x, string_value[3]);
	BN_hex2bn(&ecp->G->y, string_value[4]);
	if (!ecp->EC_POINT_set_affine_coordinates(ecp->group
	        , ecp->G->ec_point, ecp->G->x
	        , ecp->G->y, ecp->ctx))
		// err here
		/*椭圆曲线的点的长度*/
		ecp->point_bit_length = point_bit_length;
	ecp->point_byte_length = (point_bit_length + 7) / 8;

	return 1;
}


sm2_ec_key * sm2_ec_key_new(ec_param *ecp)
{
	sm2_ec_key *eck;
	eck = (sm2_ec_key *)OPENSSL_malloc(sizeof(sm2_ec_key));
	eck->d = BN_new();
	eck->P = xy_ecpoint_new(ecp);
	return eck;
}
void sm2_ec_key_free(sm2_ec_key *eck)
{
	if (eck)
	{
		BN_free(eck->d);
		xy_ecpoint_free(eck->P);
		OPENSSL_free(eck);
		eck = NULL;
	}
}
int sm2_ec_key_init(sm2_ec_key *eck, char *string_value, ec_param *ecp)
{
	int ret;
	int len;
	char *tmp;
	tmp = NULL;
	len = strlen(string_value);
	//如果长度较长，截取前面部分
	if (len > ecp->point_byte_length * 2)
	{
		len = ecp->point_byte_length * 2;
		tmp = (char *)OPENSSL_malloc(len + 2);
		memset(tmp, 0, len + 2);
		memcpy(tmp, string_value, len);
		BN_hex2bn(&eck->d, tmp);
		OPENSSL_free(tmp);
	}
	else
	{
		BN_hex2bn(&eck->d, string_value);
	}
	ret = xy_ecpoint_mul_bignum(eck->P, ecp->G, eck->d, ecp);

	return ret;
}


static unsigned long long total_length = 0;
static BYTE message_buffer[64] = {0};
static DWORD message_buffer_position = 0;
static DWORD hash[8] = {0};
static DWORD V_i[8] = {0};
static DWORD V_i_1[8] = {0};
static DWORD T_j[64] = {0};

static DWORD IV[8] =
{
	0x7380166f,
	0x4914b2b9,
	0x172442d7,
	0xda8a0600,
	0xa96f30bc,
	0x163138aa,
	0xe38dee4d,
	0xb0fb0e4e
};

void out_hex(DWORD *list1)
{
	DWORD i = 0;
	for (i = 0; i < 8; i++)
	{
		printf("%08x ", list1[i]);
	}
	printf("\r\n");
}

DWORD rotate_left(DWORD a, DWORD k)
{
	k = k % 32;
	return ((a << k) & 0xFFFFFFFF) | ((a & 0xFFFFFFFF) >> (32 - k));
}

int init_T_j()
{
	DWORD i = 0;
	for (i = 0; i < 16; i++)
	{
		T_j[i] = 0x79cc4519;
	}
	for (i = 16; i < 64; i++)
	{
		T_j[i] = 0x7a879d8a;
	}
	return 1;
}

DWORD FF_j(DWORD X, DWORD Y, DWORD Z, DWORD j)
{
	DWORD ret;
	if (0 <= j && j < 16)
	{
		ret = X ^ Y ^ Z;
	}
	else if (16 <= j && j < 64)
	{
		ret = (X & Y) | (X & Z) | (Y & Z);
	}
	return ret;
}

DWORD GG_j(DWORD X, DWORD Y, DWORD Z, DWORD j)
{
	DWORD ret;
	if (0 <= j && j < 16)
	{
		ret = X ^ Y ^ Z;
	}
	else if (16 <= j && j < 64)
	{
		ret = (X & Y) | ((~ X) & Z);
	}
	return ret;
}

DWORD P_0(DWORD X)
{
	return X ^ (rotate_left(X, 9)) ^ (rotate_left(X, 17));
}

DWORD P_1(DWORD X)
{
	return X ^ (rotate_left(X, 15)) ^ (rotate_left(X, 23));
}

int CF(DWORD *V_i, BYTE *B_i, DWORD *V_i_1)
{
	DWORD W[68];
	DWORD W_1[64];
	DWORD j;
	DWORD A, B, C, D, E, F, G, H;
	DWORD SS1, SS2, TT1, TT2;
	for (j = 0; j < 16; j++)
	{
		W[j] = B_i[j * 4 + 0] << 24
		       | B_i[j * 4 + 1] << 16
		       | B_i[j * 4 + 2] << 8
		       | B_i[j * 4 + 3];
	}
	for (j = 16; j < 68; j++)
	{
		W[j] = P_1(W[j - 16] ^ W[j - 9] ^ (rotate_left(W[j - 3], 15))) ^ (rotate_left(W[j - 13], 7)) ^ W[j - 6];
	}
	for (j = 0; j < 64; j++)
	{
		W_1[j] = W[j] ^ W[j + 4];
	}
	A = V_i[0];
	B = V_i[1];
	C = V_i[2];
	D = V_i[3];
	E = V_i[4];
	F = V_i[5];
	G = V_i[6];
	H = V_i[7];
	for (j = 0; j < 64; j++)
	{
		SS1 = rotate_left(((rotate_left(A, 12)) + E + (rotate_left(T_j[j], j))) & 0xFFFFFFFF, 7);
		SS2 = SS1 ^ (rotate_left(A, 12));
		TT1 = (FF_j(A, B, C, j) + D + SS2 + W_1[j]) & 0xFFFFFFFF;
		TT2 = (GG_j(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
		D = C;
		C = rotate_left(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = rotate_left(F, 19);
		F = E;
		E = P_0(TT2);

#if INFO
		DWORD a[8] = {A, B, C, D, E, F, G, H};
		out_hex(a);
#endif
	}
	V_i_1[0] = (A ^ V_i[0]);
	V_i_1[1] = (B ^ V_i[1]);
	V_i_1[2] = (C ^ V_i[2]);
	V_i_1[3] = (D ^ V_i[3]);
	V_i_1[4] = (E ^ V_i[4]);
	V_i_1[5] = (F ^ V_i[5]);
	V_i_1[6] = (G ^ V_i[6]);
	V_i_1[7] = (H ^ V_i[7]);
	return 1;
}
void SM3_Init()
{
	DWORD i;
	total_length = 0;
	message_buffer_position = 0;
	init_T_j();
	for (i = 0; i < 8; i++)
	{
		V_i[i] = IV[i];
	}
}
void SM3_Update(BYTE *message, DWORD length)
{
	DWORD length_org = length;
	DWORD read_byte_count = 0;
	DWORD message_position = 0;
	DWORD i;
	while (length > 0)
	{
		if (length <= 64 - message_buffer_position)
		{
			read_byte_count = length;
		}
		else   //length > 64
		{
			read_byte_count = 64 - message_buffer_position;
		}
		memcpy(&message_buffer[message_buffer_position], &message[message_position], read_byte_count);
		message_buffer_position = message_buffer_position + read_byte_count;
		if (message_buffer_position == 64)
		{
			CF(V_i, message_buffer, V_i_1);
			for (i = 0; i < 8; i++)
			{
				V_i[i] = V_i_1[i];
			}
			message_buffer_position = 0;
		}
		message_position = message_position + read_byte_count;
		length = length - read_byte_count;
	}
	total_length += length_org;
}
void SM3_Final_dword(DWORD *out_hash)
{
	DWORD i;

	total_length = total_length * 8;
	memset(&message_buffer[message_buffer_position], 0, 64 - message_buffer_position);
	if (message_buffer_position <= 64 - 1 - 8)
	{
		message_buffer[message_buffer_position] = 0x80;
		for (i = 0; i < 8; i++)
		{
			message_buffer[56 + i] = (total_length >> ((8 - 1 - i) * 8)) & 0xFF;
		}
		CF(V_i, message_buffer, V_i_1);
	}
	else
	{
		message_buffer[message_buffer_position] = 0x80;
		CF(V_i, message_buffer, V_i_1);
		for (i = 0; i < 8; i++)
		{
			V_i[i] = V_i_1[i];
		}
		message_buffer_position = 0;
		memset(message_buffer, 0, 64);
		for (i = 0; i < 8; i++)
		{
			message_buffer[56 + i] = (total_length >> ((8 - 1 - i) * 8)) & 0xFF;
		}
		CF(V_i, message_buffer, V_i_1);
	}
	for (i = 0; i < 8; i++)
	{
		out_hash[i] = V_i_1[i];
	}
}
void SM3_Final_byte(BYTE *out_hash)
{
	int i = 0;
	DWORD hash[8] = {0};
	SM3_Final_dword(hash);
	for (i = 0; i < 8; i++)
	{
		out_hash[i * 4] = (hash[i] >> 24) & 0xFF;
		out_hash[i * 4 + 1] = (hash[i] >> 16) & 0xFF;
		out_hash[i * 4 + 2] = (hash[i] >> 8) & 0xFF;
		out_hash[i * 4 + 3] = (hash[i]) & 0xFF;
	}
}
void SM3_Final(DWORD *out_hash)
{
	SM3_Final_dword(out_hash);
}

int SM3_hash(BYTE *msg, DWORD len1, DWORD *out_hash)
{
	SM3_Init();
	SM3_Update(msg, len1);
	SM3_Final(out_hash);
	return 1;
}


void show_bignum(BIGNUM *bn, int point_byte_length)
{
	char *to = BN_bn2hex(bn);
	int len1 = strlen(to);
	int remain = point_byte_length % 4;
	int j;
	int count = 0;
	for (j = 0; j < point_byte_length - len1 / 2; j++)
	{
		printf("00");

		count = count + 1;
		if (count == remain)
		{
			printf(" ");
			count = 4;
		}
		else if (count % 4 == 0)
		{
			printf(" ");
		}
	}
	for (j = 0; j < len1; j = j + 2)
	{
		printf("%c%c", to[j], to[j + 1]);
		count = count + 1;
		if (count == remain)
		{
			printf(" ");
			count = 4;
		}
		else if (count % 4 == 0)
		{
			printf(" ");
		}
	}
	OPENSSL_free(to);
}

void show_string(BYTE *string1, int length1)
{
	int j;
	for (j = 0; j < length1; j++)
	{
		printf("%02X", string1[j]);
		if ((j + 1) % 32 == 0 && (j + 1) != length1)
		{
			printf("\n");
		}
		else if ((j + 1) % 4 == 0)
		{
			printf(" ");
		}
	}
}

BYTE *KDF(BYTE *str1, int klen, int strlen1)
{
	unsigned int ct = 0x00000001;
	int group_number = ((klen + (HASH_BIT_LENGTH - 1)) / HASH_BIT_LENGTH);
	BYTE *H = (BYTE *)OPENSSL_malloc(group_number * HASH_BYTE_LENGTH);
	int i;

	for (i = 0; i < group_number; i++)
	{
		//ct复制到字符串最后，big-endian
		str1[strlen1] = (ct >> 24) & 0xFF;
		str1[strlen1 + 1] = (ct >> 16) & 0xFF;
		str1[strlen1 + 2] = (ct >> 8) & 0xFF;
		str1[strlen1 + 3] = (ct >> 0) & 0xFF;

		SM3_Init();
		SM3_Update((BYTE *)str1, strlen1 + 4);
		SM3_Final_byte((BYTE *)&H[i * HASH_BYTE_LENGTH]);
		DEFINE_SHOW_STRING((BYTE *)H, 32);

		ct = ct + 1;
	}

	return H;
}

int sm2_bn2bin(BIGNUM *bn, BYTE *bin_string, int point_byte_length);
int sm2_hex2bin(BYTE *hex_string, BYTE *bin_string, int point_byte_length)
{
	BIGNUM *b;
	int ret;
	b = BN_new();
	BN_hex2bn(&b, (char *)hex_string);
	ret = sm2_bn2bin(b, bin_string, point_byte_length);
	BN_free(b);
	return ret;
}

int sm2_bn2bin(BIGNUM *bn, BYTE *bin_string, int point_byte_length)
{
	int ret;
	int len;
	if (point_byte_length < 0)
		return 0;
	if (point_byte_length > MAX_POINT_BYTE_LENGTH)
		return 0;

	len = point_byte_length - BN_num_bytes(bn);
	if (len > MAX_POINT_BYTE_LENGTH)
	{
		return 0;
	}
	if (len < 0)
	{
		len = 0;
	}
	if (len > 0)
	{
		memset(bin_string, 0, len);
	}
	ret = BN_bn2bin(bn, &bin_string[len]);
	return ret;
}

int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point, BN_CTX *ctx);

/*------------------------------------------------------------------ python接口 ---------------------------------------------------------*/
struct py_ec_param
{
	ec_param* ecp;
	
	py_ec_param(PyObject* py_string_value, int type, int point_bit_length)
	{
		int size = PyList_Size(py_string_value);
		char** string_value = (char**)OPENSSL_malloc(sizeof(char*) * size);
		for (int i = 0; i < size; i++)
		{
			string_value[i] = PyString_AsString(PyList_GetItem(py_string_value, i));
		}
		
		ecp = ec_param_new();
		printf("%s", "ok");
		ec_param_init(ecp, string_value, type, point_bit_length);
	}
	
	~py_ec_param()
	{
		ec_param_free(ecp);
	}
};

struct py_xy_ecpoint
{
	xy_ecpoint* xyp;
	
	py_xy_ecpoint(ec_param* ecp)
	{
		xyp = xy_ecpoint_new(ecp);
	}
	
	static int mul_bignum(py_xy_ecpoint *result, py_xy_ecpoint *a, BIGNUM *number, ec_param *ecp)
	{	
		return xy_ecpoint_mul_bignum(result->xyp, a->xyp, number, ecp);
	}
	
	static int add_xy_ecpoint(py_xy_ecpoint *result, py_xy_ecpoint *a, py_xy_ecpoint *b, ec_param *ecp)
	{
		return xy_ecpoint_add_xy_ecpoint(result->xyp, a->xyp, b->xyp, ecp);
	}
	
	static int init_xy(py_xy_ecpoint *result, BIGNUM *x, BIGNUM *y, ec_param *ecp)
	{
		return xy_ecpoint_init_xy(result->xyp, x, y, ecp);
	}
	
	static int init_ec_point(py_xy_ecpoint *result, EC_POINT *ec_point, ec_param *ecp)
	{
		return xy_ecpoint_init_ec_point(result->xyp, ec_point, ecp);
	}
	
	~py_xy_ecpoint()
	{
		xy_ecpoint_free(xyp);
	}
};

struct PYSM2
{
	static BIGNUM* hex2bn(PyObject* str)
	{
		char *sbuf = 0; 
		Py_ssize_t slen;
		BIGNUM* bn = 0;
		if (PyBytes_Check(str))
		{
			slen =  PyBytes_Size(str);
			sbuf = (char*)PyBytes_AsString(str);
		}
		else 
		{
			PyErr_SetString(PyExc_MemoryError, "Type error");
			return 0;
		}
		if (!BN_hex2bn(&bn, (const char*)sbuf))
			return 0;
		return bn;
	}

	static EC_GROUP* ec_group_new_curve_gfp(BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
	{
		return EC_GROUP_new_curve_GFp(p, a, b, ctx);
	}
	
	static EC_POINT *ec_point_new(EC_GROUP *group)
	{
		return EC_POINT_new(group);
	}
	
	static void ec_point_free(EC_POINT *point)
	{
		return EC_POINT_free(point);
	}
	
	static BN_CTX *bn_ctx_new()
	{
		return BN_CTX_new();
	}
	
	static void bn_ctx_free(BN_CTX *c)
	{
		return BN_CTX_free(c);
	}
	
	static void bn_free(BIGNUM *a)
	{
		return BN_free(a);
	}
	
	static int ec_point_set_affine_coordinates_gfp(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, 
		const BIGNUM *y, BN_CTX *ctx)
	{
		return 	EC_POINT_set_affine_coordinates_GFp(group, p, x, y, ctx);
	}

	static EC_GROUP* EC_GROUP_new_curve_GF2m(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
	{
		return EC_GROUP_new_curve_GF2m(p, a, b, ctx);
	}
	
	static int ec_point_set_affine_coordinates_gf2m(const EC_GROUP *group, EC_POINT *p, const BIGNUM *x, 
		const BIGNUM *y,  BN_CTX *ctx)
	{
		return EC_POINT_set_affine_coordinates_GF2m(group, p, x, y, ctx);
	}
	
	static int ec_group_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor)
	{
		return EC_GROUP_set_generator(group, generator, order, cofactor);
	}
						   
	static sm2_sign_st* sm2_sign(ec_param *ecp, sm2_sign_st* sign, char* message_digest)
	{
		sm2_hash Z_A;
		sm2_hash e;
		BIGNUM *e_bn;

		BIGNUM *r;
		BIGNUM *s;
		BIGNUM *tmp1;

		BIGNUM *P_x;
		BIGNUM *P_y;
		BIGNUM *d;
		BIGNUM *k;
		xy_ecpoint *xy1;

		e_bn = BN_new();
		r = BN_new();
		s = BN_new();
		tmp1 = BN_new();
		P_x = BN_new();
		P_y = BN_new();
		d = BN_new();
		k = BN_new();
		xy1 = xy_ecpoint_new(ecp);
		
		BN_bin2bn(sign->public_key.x, ecp->point_byte_length, P_x);
		BN_bin2bn(sign->public_key.y, ecp->point_byte_length, P_y);
		BN_bin2bn(sign->private_key, ecp->point_byte_length, d);
		BN_bin2bn(sign->k, ecp->point_byte_length, k);

		memset(&Z_A, 0, sizeof(Z_A));
		Z_A.buffer[0] = ((sign->ENTL * 8) >> 8) & 0xFF;
		Z_A.buffer[1] = (sign->ENTL * 8) & 0xFF;
		Z_A.position = Z_A.position + 2;
		BUFFER_APPEND_STRING(Z_A.buffer, Z_A.position, sign->ENTL, sign->ID);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->a);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->b);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->x);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->y);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_x);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_y);
		DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
		SM3_Init();
		SM3_Update(Z_A.buffer, Z_A.position);
		SM3_Final_byte(Z_A.hash);
		memcpy(sign->Z, Z_A.hash, HASH_BYTE_LENGTH);

		DEFINE_SHOW_STRING(Z_A.hash, HASH_BYTE_LENGTH);

		memset(&e, 0, sizeof(e));
		BUFFER_APPEND_STRING(e.buffer, e.position, HASH_BYTE_LENGTH, Z_A.hash);
		BUFFER_APPEND_STRING(e.buffer, e.position, strlen(message_digest), (BYTE *)message_digest);
		SM3_Init();
		SM3_Update(e.buffer, e.position);
		SM3_Final_byte(e.hash);
		DEFINE_SHOW_STRING(e.hash, HASH_BYTE_LENGTH);
		DEFINE_SHOW_STRING(sign->k, ecp->point_byte_length);

		BN_bin2bn(e.hash, HASH_BYTE_LENGTH, e_bn);

		xy_ecpoint_mul_bignum(xy1, ecp->G, k, ecp);
		BN_zero(r);
		BN_mod_add(r, e_bn, xy1->x, ecp->n, ecp->ctx);

		BN_one(s);
		BN_add(s, s, d);
		BN_mod_inverse(s, s, ecp->n, ecp->ctx);  //求模反

		BN_mul(tmp1, r, d, ecp->ctx);
		BN_sub(tmp1, k, tmp1);
		BN_mod_mul(s, s, tmp1, ecp->n, ecp->ctx);

		sm2_bn2bin(r, sign->r, ecp->point_byte_length);
		sm2_bn2bin(s, sign->s, ecp->point_byte_length);

		DEFINE_SHOW_BIGNUM(r);
		DEFINE_SHOW_BIGNUM(s);

		BN_free(e_bn);
		BN_free(r);
		BN_free(s);
		BN_free(tmp1);
		BN_free(P_x);
		BN_free(P_y);
		BN_free(d);
		BN_free(k);
		xy_ecpoint_free(xy1);
		return sign;
	}

	static sm2_sign_st* sm2_verify(ec_param *ecp, sm2_sign_st* sign)
	{
		sm2_hash e;
		BIGNUM *e_bn;
		BIGNUM *t;
		BIGNUM *R;
		xy_ecpoint *result;
		xy_ecpoint *result1;
		xy_ecpoint *result2;
		xy_ecpoint *P_A;
		BIGNUM *r;
		BIGNUM *s;
		BIGNUM *P_x;
		BIGNUM *P_y;

		e_bn = BN_new();
		t = BN_new();
		R = BN_new();
		result = xy_ecpoint_new(ecp);
		result1 = xy_ecpoint_new(ecp);
		result2 = xy_ecpoint_new(ecp);
		P_A = xy_ecpoint_new(ecp);
		r = BN_new();
		s = BN_new();
		P_x = BN_new();
		P_y = BN_new();
		
		BN_bin2bn(sign->r, ecp->point_byte_length, r);
		BN_bin2bn(sign->s, ecp->point_byte_length, s);
		BN_bin2bn(sign->public_key.x, ecp->point_byte_length, P_x);
		BN_bin2bn(sign->public_key.y, ecp->point_byte_length, P_y);
		xy_ecpoint_init_xy(P_A, P_x, P_y, ecp);

		memset(&e, 0, sizeof(e));
		BUFFER_APPEND_STRING(e.buffer, e.position, HASH_BYTE_LENGTH, sign->Z);
		BUFFER_APPEND_STRING(e.buffer, e.position, sign->message_byte_length, (BYTE*)sign->message);
		SM3_Init();
		SM3_Update(e.buffer, e.position);
		SM3_Final_byte(e.hash);
		BN_bin2bn(e.hash, HASH_BYTE_LENGTH, e_bn);
		DEFINE_SHOW_BIGNUM(e_bn);

		BN_mod_add(t, r, s, ecp->n, ecp->ctx);
		xy_ecpoint_mul_bignum(result1, ecp->G, s, ecp);
		xy_ecpoint_mul_bignum(result2, P_A, t, ecp);
		xy_ecpoint_add_xy_ecpoint(result, result1, result2, ecp);

		BN_mod_add(R, e_bn, result->x, ecp->n, ecp->ctx);

		sm2_bn2bin(R, sign->R, ecp->point_byte_length);

		DEFINE_SHOW_STRING(sign->R, ecp->point_byte_length);

		BN_free(e_bn);
		BN_free(t);
		BN_free(R);
		xy_ecpoint_free(result);
		xy_ecpoint_free(result1);
		xy_ecpoint_free(result2);
		xy_ecpoint_free(P_A);
		BN_free(r);
		BN_free(s);
		BN_free(P_x);
		BN_free(P_y);
		return sign;
	}
	
	static message_st* sm2_encrypt(ec_param *ecp, message_st* message_data)
	{
		BIGNUM *P_x;
		BIGNUM *P_y;
		//BIGNUM *d;
		BIGNUM *k;
		xy_ecpoint *P;
		xy_ecpoint *xy1;
		xy_ecpoint *xy2;
		int pos1;
		BYTE *t;
		int i;
		sm2_hash local_C_3;

		P_x = BN_new();
		P_y = BN_new();
		k = BN_new();
		P = xy_ecpoint_new(ecp);
		xy1 = xy_ecpoint_new(ecp);
		xy2 = xy_ecpoint_new(ecp);
		
		BN_bin2bn(message_data->public_key.x, ecp->point_byte_length, P_x);
		BN_bin2bn(message_data->public_key.y, ecp->point_byte_length, P_y);
		BN_bin2bn(message_data->k, ecp->point_byte_length, k);

		xy_ecpoint_init_xy(P, P_x, P_y, ecp);
		xy_ecpoint_mul_bignum(xy1, ecp->G, k, ecp);
		xy_ecpoint_mul_bignum(xy2, P, k, ecp);

		pos1 = 0;
		message_data->C_1[0] = '\x04';
		pos1 = pos1 + 1;
		BUFFER_APPEND_BIGNUM(message_data->C_1, pos1, ecp->point_byte_length, xy1->x);
		BUFFER_APPEND_BIGNUM(message_data->C_1, pos1, ecp->point_byte_length, xy1->y);

		pos1 = 0;
		BUFFER_APPEND_BIGNUM(message_data->C_2, pos1, ecp->point_byte_length, xy2->x);
		BUFFER_APPEND_BIGNUM(message_data->C_2, pos1, ecp->point_byte_length, xy2->y);

		t = KDF((BYTE *)message_data->C_2, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);
		for (i = 0; i < message_data->message_byte_length; i++)
		{
			message_data->C_2[i] = t[i] ^ message_data->message[i];
		}
		OPENSSL_free(t);

		//º∆À„C_3
		memset(&local_C_3, 0, sizeof(local_C_3));
		BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length
			, xy2->x);
		BUFFER_APPEND_STRING(local_C_3.buffer, local_C_3.position, message_data->message_byte_length
			, message_data->message);
		BUFFER_APPEND_BIGNUM(local_C_3.buffer, local_C_3.position, ecp->point_byte_length
			, xy2->y);
		SM3_Init();
		SM3_Update((BYTE *)local_C_3.buffer, local_C_3.position);
		SM3_Final_byte(local_C_3.hash);
		memcpy(message_data->C_3, (char *)local_C_3.hash, HASH_BYTE_LENGTH);

		pos1 = 0;
		BUFFER_APPEND_STRING(message_data->C, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length
			, message_data->C_1);
		BUFFER_APPEND_STRING(message_data->C, pos1, message_data->message_byte_length
			, message_data->C_2);
		BUFFER_APPEND_STRING(message_data->C, pos1, HASH_BYTE_LENGTH
			, message_data->C_3);

		printf("encrypt: \n");
		DEFINE_SHOW_STRING(message_data->C, 256);

		BN_free(P_x);
		BN_free(P_y);
		BN_free(k);
		xy_ecpoint_free(P);
		xy_ecpoint_free(xy1);
		xy_ecpoint_free(xy2);

		return message_data;
	}

	static message_st* sm2_decrypt(ec_param *ecp, message_st *message_data)
	{
		int pos1;
		int pos2;
		xy_ecpoint *xy1;
		xy_ecpoint *xy2;
		BIGNUM *d;
		BYTE KDF_buffer[MAX_POINT_BYTE_LENGTH * 2];
		BYTE *t;
		int i;

		xy1 = xy_ecpoint_new(ecp);
		xy2 = xy_ecpoint_new(ecp);
		d = BN_new();

		pos1 = 0;
		pos2 = 0;
		BUFFER_APPEND_STRING(message_data->C_1, pos1, 1 + ecp->point_byte_length + ecp->point_byte_length
			, &message_data->C[pos2]);
		pos2 = pos2 + pos1;
		pos1 = 0;
		BUFFER_APPEND_STRING(message_data->C_2, pos1, message_data->message_byte_length
			, &message_data->C[pos2]);
		pos2 = pos2 + pos1;
		pos1 = 0;
		BUFFER_APPEND_STRING(message_data->C_3, pos1, HASH_BYTE_LENGTH
			, &message_data->C[pos2]);
		pos2 = pos2 + pos1;

		BN_bin2bn(&message_data->C_1[1], ecp->point_byte_length, xy1->x);
		BN_bin2bn(&message_data->C_1[1 + ecp->point_byte_length], ecp->point_byte_length, xy1->y);

		BN_bin2bn(message_data->private_key, ecp->point_byte_length, d);
		xy_ecpoint_init_xy(xy1, xy1->x, xy1->y, ecp);
		xy_ecpoint_mul_bignum(xy2, xy1, d, ecp);

		pos1 = 0;
		memset(KDF_buffer, 0, sizeof(KDF_buffer));
		BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->x);
		BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, xy2->y);
		DEFINE_SHOW_BIGNUM(d);
		DEFINE_SHOW_BIGNUM(xy2->x);
		DEFINE_SHOW_BIGNUM(xy2->y);
		t = KDF((BYTE *)KDF_buffer, message_data->klen_bit, ecp->point_byte_length + ecp->point_byte_length);

		for (i = 0; i < message_data->message_byte_length; i++)
		{
			message_data->decrypt[i] = t[i] ^ message_data->C_2[i];
		}
		OPENSSL_free(t);

		xy_ecpoint_free(xy1);
		xy_ecpoint_free(xy2);
		BN_free(d);

		return message_data;
	}

	static int dh_step1(sm2_dh_st *dh_data, BYTE *dh_d, BYTE *dh_r, ec_param *ecp)
	{
		sm2_ec_key *key_A;
		BIGNUM *P_x;
		BIGNUM *P_y;
		BIGNUM *d;
		BIGNUM *r;
		sm2_hash Z_A;
		xy_ecpoint *point_R;

		key_A = sm2_ec_key_new(ecp);
		P_x = BN_new();
		P_y = BN_new();
		d = BN_new();
		r = BN_new();
		point_R = xy_ecpoint_new(ecp);

		sm2_ec_key_init(key_A, (char *)dh_d, ecp);

		sm2_hex2bin((BYTE *)dh_r, dh_data->r, ecp->point_byte_length);
		sm2_bn2bin(key_A->d, dh_data->private_key, ecp->point_byte_length);
		sm2_bn2bin(key_A->P->x, dh_data->public_key.x, ecp->point_byte_length);
		sm2_bn2bin(key_A->P->y, dh_data->public_key.y, ecp->point_byte_length);

		BN_bin2bn(dh_data->public_key.x, ecp->point_byte_length, P_x);
		BN_bin2bn(dh_data->public_key.y, ecp->point_byte_length, P_y);
		BN_bin2bn(dh_data->private_key, ecp->point_byte_length, d);
		BN_bin2bn(dh_data->r, ecp->point_byte_length, r);

		memset(&Z_A, 0, sizeof(Z_A));
		Z_A.buffer[0] = ((dh_data->ENTL * 8) >> 8) & 0xFF;
		Z_A.buffer[1] = (dh_data->ENTL * 8) & 0xFF;
		Z_A.position = Z_A.position + 2;
		BUFFER_APPEND_STRING(Z_A.buffer, Z_A.position, dh_data->ENTL, dh_data->ID);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->a);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->b);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->x);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, ecp->G->y);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_x);
		BUFFER_APPEND_BIGNUM(Z_A.buffer, Z_A.position, ecp->point_byte_length, P_y);
		DEFINE_SHOW_STRING(Z_A.buffer, Z_A.position);
		SM3_Init();
		SM3_Update(Z_A.buffer, Z_A.position);
		SM3_Final_byte(Z_A.hash);
		
		memcpy(dh_data->Z, Z_A.hash, HASH_BYTE_LENGTH);

		xy_ecpoint_mul_bignum(point_R, ecp->G, r, ecp);
		sm2_bn2bin(point_R->x, dh_data->R.x, ecp->point_byte_length);
		sm2_bn2bin(point_R->y, dh_data->R.y, ecp->point_byte_length);

		DEFINE_SHOW_STRING(dh_data->Z, HASH_BYTE_LENGTH);
		DEFINE_SHOW_BIGNUM(r);
		DEFINE_SHOW_STRING(dh_data->R.x, ecp->point_byte_length);
		DEFINE_SHOW_STRING(dh_data->R.y, ecp->point_byte_length);

		BN_free(P_x);
		BN_free(P_y);
		BN_free(d);
		BN_free(r);

		sm2_ec_key_free(key_A);
		xy_ecpoint_free(point_R);

		return 0;
	}

	//order = 0, A,B顺序
	//order = 1, B,A顺序，计算KDF时按不同顺序有变化，其他地方不影响
	static int dh_step2(sm2_dh_st *dh_data_A, sm2_dh_st *dh_data_B, ec_param *ecp, int order)
	{
		BIGNUM *x_1;
		BIGNUM *y_1;
		BIGNUM *x_2;
		BIGNUM *y_2;
		BIGNUM *_x_1;
		BIGNUM *_x_2;
		xy_ecpoint *point_R;
		xy_ecpoint *point_0;
		xy_ecpoint *point_1;
		xy_ecpoint *point_2;
		BIGNUM *P_A_x;
		BIGNUM *P_A_y;
		xy_ecpoint *point_P_A;
		BIGNUM *h;
		BIGNUM *t_B;
		BIGNUM *d_B;
		BIGNUM *r_B;
		BIGNUM *num_2_127;
		BYTE *K;
		BYTE KDF_buffer[1024];
		int pos1;
		sm2_hash hash1;

		x_1 = BN_new();
		y_1 = BN_new();
		x_2 = BN_new();
		y_2 = BN_new();
		_x_1 = BN_new();
		_x_2 = BN_new();
		point_R = xy_ecpoint_new(ecp);
		point_0 = xy_ecpoint_new(ecp);
		point_1 = xy_ecpoint_new(ecp);
		point_2 = xy_ecpoint_new(ecp);
		P_A_x = BN_new();
		P_A_y = BN_new();
		point_P_A = xy_ecpoint_new(ecp);
		h = BN_new();
		t_B = BN_new();
		d_B = BN_new();
		r_B = BN_new();
		num_2_127 = BN_new();

		BN_bin2bn(dh_data_A->R.x, ecp->point_byte_length, x_1);
		BN_bin2bn(dh_data_A->R.y, ecp->point_byte_length, y_1);
		BN_bin2bn(dh_data_A->public_key.x, ecp->point_byte_length, P_A_x);
		BN_bin2bn(dh_data_A->public_key.y, ecp->point_byte_length, P_A_y);
		xy_ecpoint_init_xy(point_P_A, P_A_x, P_A_y, ecp);
		BN_bin2bn(dh_data_B->R.x, ecp->point_byte_length, x_2);
		BN_bin2bn(dh_data_B->R.y, ecp->point_byte_length, y_2);
		BN_bin2bn(dh_data_B->private_key, ecp->point_byte_length, d_B);
		BN_bin2bn(dh_data_B->r, ecp->point_byte_length, r_B);

		BN_hex2bn(&num_2_127, "80000000000000000000000000000000");

		BN_mod(_x_2, x_2, num_2_127, ecp->ctx);
		BN_add(_x_2, _x_2, num_2_127);

		BN_mul(t_B, _x_2, r_B, ecp->ctx);
		BN_add(t_B, t_B, d_B);
		BN_mod(t_B, t_B, ecp->n, ecp->ctx);
		int sm2_param_dh_h[2] = {1, 4};

		BN_set_word(h, sm2_param_dh_h[ecp->type]);
		BN_mul(t_B, t_B, h, ecp->ctx);

		BN_mod(_x_1, x_1, num_2_127, ecp->ctx);
		BN_add(_x_1, _x_1, num_2_127);

		xy_ecpoint_init_xy(point_R, x_1, y_1, ecp);
		xy_ecpoint_mul_bignum(point_0, point_R, _x_1, ecp);
		xy_ecpoint_add_xy_ecpoint(point_1, point_0, point_P_A, ecp);
		xy_ecpoint_mul_bignum(point_2, point_1, t_B, ecp);

		DEFINE_SHOW_BIGNUM(point_0->x);
		DEFINE_SHOW_BIGNUM(point_0->y);
		DEFINE_SHOW_BIGNUM(point_1->x);
		DEFINE_SHOW_BIGNUM(point_1->y);
		DEFINE_SHOW_BIGNUM(point_2->x);
		DEFINE_SHOW_BIGNUM(point_2->y);

		memset(KDF_buffer, 0, sizeof(KDF_buffer));
		pos1 = 0;
		BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, point_2->x);
		BUFFER_APPEND_BIGNUM(KDF_buffer, pos1, ecp->point_byte_length, point_2->y);
		if (ORDER_A_B == order)
		{
			BUFFER_APPEND_STRING(KDF_buffer, pos1, HASH_BYTE_LENGTH, dh_data_A->Z);
			BUFFER_APPEND_STRING(KDF_buffer, pos1, HASH_BYTE_LENGTH, dh_data_B->Z);
		}
		else
		{
			BUFFER_APPEND_STRING(KDF_buffer, pos1, HASH_BYTE_LENGTH, dh_data_B->Z);
			BUFFER_APPEND_STRING(KDF_buffer, pos1, HASH_BYTE_LENGTH, dh_data_A->Z);
		}

		K = KDF(KDF_buffer, dh_data_B->klen_bit, pos1);
		memcpy(dh_data_B->K, K, dh_data_B->klen_bit / 8);
		OPENSSL_free(K);

		memset(&hash1, 0, sizeof(hash1));
		BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, point_2->x);
		if (ORDER_A_B == order)
		{
			BUFFER_APPEND_STRING(hash1.buffer, hash1.position, HASH_BYTE_LENGTH, dh_data_A->Z);
			BUFFER_APPEND_STRING(hash1.buffer, hash1.position, HASH_BYTE_LENGTH, dh_data_B->Z);
			BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, x_1);
			BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, y_1);
			BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, x_2);
			BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, y_2);
		}
		else
		{
			BUFFER_APPEND_STRING(hash1.buffer, hash1.position, HASH_BYTE_LENGTH, dh_data_B->Z);
			BUFFER_APPEND_STRING(hash1.buffer, hash1.position, HASH_BYTE_LENGTH, dh_data_A->Z);
			BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, x_2);
			BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, y_2);
			BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, x_1);
			BUFFER_APPEND_BIGNUM(hash1.buffer, hash1.position, ecp->point_byte_length, y_1);
		}
		SM3_Init();
		SM3_Update(hash1.buffer, hash1.position);
		SM3_Final_byte(hash1.hash);

		DEFINE_SHOW_STRING(hash1.buffer, hash1.position);


		memset(&dh_data_B->hash_tmp_data, 0, sizeof(dh_data_B->hash_tmp_data));
		dh_data_B->hash_tmp_data.position = 1;
		BUFFER_APPEND_BIGNUM(dh_data_B->hash_tmp_data.buffer, dh_data_B->hash_tmp_data.position
			, ecp->point_byte_length, point_2->y);
		BUFFER_APPEND_STRING(dh_data_B->hash_tmp_data.buffer, dh_data_B->hash_tmp_data.position
			, HASH_BYTE_LENGTH, hash1.hash);

		BN_free(x_1);
		BN_free(y_1);
		BN_free(x_2);
		BN_free(y_2);
		BN_free(_x_1);
		BN_free(_x_2);
		xy_ecpoint_free(point_R);
		xy_ecpoint_free(point_0);
		xy_ecpoint_free(point_1);
		xy_ecpoint_free(point_2);
		BN_free(P_A_x);
		BN_free(P_A_y);
		xy_ecpoint_free(point_P_A);
		BN_free(h);
		BN_free(t_B);
		BN_free(d_B);
		BN_free(r_B);
		BN_free(num_2_127);

		return 0;
	}
};

/**
 * \brief          SM4 context structure
 */
typedef struct
{
	int mode;                   /*!<  encrypt/decrypt   */
	unsigned long sk[32];       /*!<  SM4 subkeys       */
}
sm4_context;

struct PYSM4
{

	#define SM4_ENCRYPT     1
	#define SM4_DECRYPT     0


	/*
	 * 32-bit integer manipulation macros (big endian)
	 */
	#ifndef GET_ULONG_BE
	#define GET_ULONG_BE(n,b,i)                             \
	{                                                       \
		(n) = ( (unsigned long) (b)[(i)    ] << 24 )        \
			| ( (unsigned long) (b)[(i) + 1] << 16 )        \
			| ( (unsigned long) (b)[(i) + 2] <<  8 )        \
			| ( (unsigned long) (b)[(i) + 3]       );       \
	}
	#endif

	#ifndef PUT_ULONG_BE
	#define PUT_ULONG_BE(n,b,i)                             \
	{                                                       \
		(b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
		(b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
		(b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
		(b)[(i) + 3] = (unsigned char) ( (n)       );       \
	}
	#endif

	/*
	 *rotate shift left marco definition
	 *
	 */
	#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
	#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

	#define SWAP(a,b) { unsigned long t = a; a = b; b = t; t = 0; }

	/*
	 * Expanded SM4 S-boxes
	 /* Sbox table: 8bits input convert to 8 bits output*/
	 






	/*
	 * private function:
	 * look up in SboxTable and get the related value.
	 * args:    [in] inch: 0x00~0xFF (8 bits unsigned value).
	 */
	static unsigned char sm4Sbox(unsigned char inch)
	{
		static const unsigned char SboxTable[16][16] = 
		{
		{0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05},
		{0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99},
		{0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62},
		{0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6},
		{0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8},
		{0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35},
		{0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87},
		{0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e},
		{0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1},
		{0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3},
		{0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f},
		{0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51},
		{0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8},
		{0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0},
		{0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84},
		{0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48}
		};
	
		unsigned char *pTable = (unsigned char *)SboxTable;
		unsigned char retVal = (unsigned char)(pTable[inch]);
		return retVal;
	}

	/*
	 * private F(Lt) function:
	 * "T algorithm" == "L algorithm" + "t algorithm".
	 * args:    [in] a: a is a 32 bits unsigned value;
	 * return: c: c is calculated with line algorithm "L" and nonline algorithm "t"
	 */
	static unsigned long sm4Lt(unsigned long ka)
	{
		unsigned long bb = 0;
		unsigned long c = 0;
		unsigned char a[4];
		unsigned char b[4];
		PUT_ULONG_BE(ka,a,0)
		b[0] = sm4Sbox(a[0]);
		b[1] = sm4Sbox(a[1]);
		b[2] = sm4Sbox(a[2]);
		b[3] = sm4Sbox(a[3]);
		GET_ULONG_BE(bb,b,0)
		c =bb^(ROTL(bb, 2))^(ROTL(bb, 10))^(ROTL(bb, 18))^(ROTL(bb, 24));
		return c;
	}

	/*
	 * private F function:
	 * Calculating and getting encryption/decryption contents.
	 * args:    [in] x0: original contents;
	 * args:    [in] x1: original contents;
	 * args:    [in] x2: original contents;
	 * args:    [in] x3: original contents;
	 * args:    [in] rk: encryption/decryption key;
	 * return the contents of encryption/decryption contents.
	 */
	static unsigned long sm4F(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3, unsigned long rk)
	{
		return (x0^sm4Lt(x1^x2^x3^rk));
	}


	/* private function:
	 * Calculating round encryption key.
	 * args:    [in] a: a is a 32 bits unsigned value;
	 * return: sk[i]: i{0,1,2,3,...31}.
	 */
	static unsigned long sm4CalciRK(unsigned long ka)
	{
		unsigned long bb = 0;
		unsigned long rk = 0;
		unsigned char a[4];
		unsigned char b[4];
		PUT_ULONG_BE(ka,a,0)
		b[0] = sm4Sbox(a[0]);
		b[1] = sm4Sbox(a[1]);
		b[2] = sm4Sbox(a[2]);
		b[3] = sm4Sbox(a[3]);
		GET_ULONG_BE(bb,b,0)
		rk = bb^(ROTL(bb, 13))^(ROTL(bb, 23));
		return rk;
	}

	static void setkey( unsigned long SK[32], unsigned char key[16] )
	{
		/* fixed parameter */
		static const unsigned long CK[32] =
		{
		0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
		0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
		0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
		0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
		0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
		0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
		0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
		0x10171e25,0x2c333a41,0x484f565d,0x646b7279
		};
	
		unsigned long MK[4];
		unsigned long k[36];
		unsigned long i = 0;

		GET_ULONG_BE( MK[0], key, 0 );
		GET_ULONG_BE( MK[1], key, 4 );
		GET_ULONG_BE( MK[2], key, 8 );
		GET_ULONG_BE( MK[3], key, 12 );
		
			/* System parameter */
		static const unsigned long FK[4] = {0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc};
		
		k[0] = MK[0]^FK[0];
		k[1] = MK[1]^FK[1];
		k[2] = MK[2]^FK[2];
		k[3] = MK[3]^FK[3];
		for(; i<32; i++)
		{
			k[i+4] = k[i] ^ (sm4CalciRK(k[i+1]^k[i+2]^k[i+3]^CK[i]));
			SK[i] = k[i+4];
		}

	}

	/*
	 * SM4 standard one round processing
	 *
	 */
	static void one_round( unsigned long sk[32],
						unsigned char input[16],
						unsigned char output[16] )
	{
		unsigned long i = 0;
		unsigned long ulbuf[36];

		memset(ulbuf, 0, sizeof(ulbuf));
		GET_ULONG_BE( ulbuf[0], input, 0 )
		GET_ULONG_BE( ulbuf[1], input, 4 )
		GET_ULONG_BE( ulbuf[2], input, 8 )
		GET_ULONG_BE( ulbuf[3], input, 12 )
		while(i<32)
		{
			ulbuf[i+4] = sm4F(ulbuf[i], ulbuf[i+1], ulbuf[i+2], ulbuf[i+3], sk[i]);
	// #ifdef _DEBUG
	//        	printf("rk(%02d) = 0x%08x,  X(%02d) = 0x%08x \n",i,sk[i], i, ulbuf[i+4] );
	// #endif
			i++;
		}
		PUT_ULONG_BE(ulbuf[35],output,0);
		PUT_ULONG_BE(ulbuf[34],output,4);
		PUT_ULONG_BE(ulbuf[33],output,8);
		PUT_ULONG_BE(ulbuf[32],output,12);
	}

	/*
	 * SM4 key schedule (128-bit, encryption)
	 */
	void setkey_enc( sm4_context *ctx, unsigned char key[16] )
	{
		ctx->mode = SM4_ENCRYPT;
		setkey( ctx->sk, key );
	}

	/*
	 * SM4 key schedule (128-bit, decryption)
	 */
	void setkey_dec( sm4_context *ctx, unsigned char key[16] )
	{
		int i;
		ctx->mode = SM4_ENCRYPT;
		setkey( ctx->sk, key );
		for( i = 0; i < 16; i ++ )
		{
			SWAP( ctx->sk[ i ], ctx->sk[ 31-i] );
		}
	}


	/*
	 * SM4-ECB block encryption/decryption
	 */

	void crypt_ecb( sm4_context *ctx,
					   int mode,
					   int length,
					   unsigned char *input,
					   unsigned char *output)
	{
		while( length > 0 )
		{
			one_round( ctx->sk, input, output );
			input  += 16;
			output += 16;
			length -= 16;
		}

	}

	/*
	 * SM4-CBC buffer encryption/decryption
	 */
	void crypt_cbc( sm4_context *ctx,
						int mode,
						int length,
						unsigned char iv[16],
						unsigned char *input,
						unsigned char *output )
	{
		int i;
		unsigned char temp[16];

		if( mode == SM4_ENCRYPT )
		{
			while( length > 0 )
			{
				for( i = 0; i < 16; i++ )
					output[i] = (unsigned char)( input[i] ^ iv[i] );

				one_round( ctx->sk, output, output );
				memcpy( iv, output, 16 );

				input  += 16;
				output += 16;
				length -= 16;
			}
		}
		else /* SM4_DECRYPT */
		{
			while( length > 0 )
			{
				memcpy( temp, input, 16 );
				one_round( ctx->sk, input, output );

				for( i = 0; i < 16; i++ )
					output[i] = (unsigned char)( output[i] ^ iv[i] );

				memcpy( iv, temp, 16 );

				input  += 16;
				output += 16;
				length -= 16;
			}
		}
	}
};

%}