%constant int AES_BLOCK_SIZE = AES_BLOCK_SIZE;
%constant int AES_ENCRYPT = AES_ENCRYPT;
%constant int AES_DECRYPT = AES_DECRYPT;

%inline %{

struct PYAES
{
	static PyObject* encrypt(PyObject* input, PyObject* key, const int enc)
	{
		unsigned char *inputbuf = 0, *keybuf = 0; 
		Py_ssize_t inputlen, keylen;

	    AES_KEY *aeskey = (AES_KEY *)PyMem_Malloc(sizeof(AES_KEY));
		if (aeskey == 0)
		{
			PyErr_SetString(PyExc_MemoryError, "Insufficient memory for AES key.");
			return 0;
		}
		
		if (PyBytes_Check(input) && PyBytes_Check(key))
		{
			inputlen =  PyBytes_Size(input);
			keylen = PyBytes_Size(key);
			inputbuf = (unsigned char*)PyBytes_AsString(input);
			keybuf = (unsigned char*)PyBytes_AsString(key);
		}
		else 
		{
			PyErr_SetString(PyExc_MemoryError, "Type error");
			return 0;
		}
		
		int outlen = inputlen > keylen? inputlen : keylen;
		void* outbuf = PyMem_Malloc(outlen);
		memset(outbuf, 0, outlen);
		if (keylen != 16 && keylen != 24 && keylen != 32)
		{
			PyErr_SetString(PyExc_MemoryError, "Key length error");
			return 0;
		}
		if (outbuf != 0)
		{
			if (enc == AES_ENCRYPT)
			{
				AES_set_encrypt_key((const unsigned char*)keybuf, keylen * 8, aeskey);
				AES_encrypt((const unsigned char*)inputbuf, (unsigned char*)outbuf, aeskey);
			}
			else if (enc == AES_DECRYPT)
			{
				AES_set_decrypt_key((const unsigned char*)keybuf, keylen * 8, aeskey);
				AES_decrypt((const unsigned char*)inputbuf, (unsigned char*)outbuf, aeskey);
			}
		}
		PyMem_Free((void*)aeskey);
		PyObject* bytes =  PyBytes_FromStringAndSize((const char*)outbuf, outlen);
		PyMem_Free((void*)outbuf);
		return bytes;
	}
	
	static PyObject* encrypt_ecb(PyObject* input, PyObject* key, const int enc)
	{
		unsigned char *inputbuf = 0, *keybuf = 0; 
		Py_ssize_t inputlen, keylen;

	    AES_KEY *aeskey = (AES_KEY *)PyMem_Malloc(sizeof(AES_KEY));
		if (aeskey == 0)
		{
			PyErr_SetString(PyExc_MemoryError, "Insufficient memory for AES key.");
			return 0;
		}
		
		if (PyBytes_Check(input) && PyBytes_Check(key))
		{
			inputlen =  PyBytes_Size(input);
			keylen = PyBytes_Size(key);
			inputbuf = (unsigned char*)PyBytes_AsString(input);
			keybuf = (unsigned char*)PyBytes_AsString(key);
		}
		else 
		{
			PyErr_SetString(PyExc_MemoryError, "Type error");
			return 0;
		}
		
		int outlen = inputlen > keylen? inputlen : keylen;
		void* outbuf = PyMem_Malloc(outlen);
		memset(outbuf, 0, outlen);
		if (keylen != 16 && keylen != 24 && keylen != 32)
		{
			PyErr_SetString(PyExc_MemoryError, "Key length error");
			return 0;
		}
		if (outbuf != 0)
		{
			if (enc == AES_ENCRYPT)
			{
				AES_set_encrypt_key((const unsigned char*)keybuf, keylen * 8, aeskey);
				AES_ecb_encrypt((const unsigned char*)inputbuf, (unsigned char*)outbuf, aeskey, enc);
			}
			else if (enc == AES_DECRYPT)
			{
				AES_set_decrypt_key((const unsigned char*)keybuf, keylen * 8, aeskey);
				AES_ecb_encrypt((const unsigned char*)inputbuf, (unsigned char*)outbuf, aeskey, enc);
			}
		}
		PyMem_Free((void*)aeskey);
		PyObject* bytes =  PyBytes_FromStringAndSize((const char*)outbuf, outlen);
		PyMem_Free((void*)outbuf);
		return bytes;
	}
	
	static PyObject* encrypt_cbc(PyObject* input, PyObject* key, PyObject* iv, const int enc)
	{
		unsigned char *inputbuf = 0, *keybuf = 0, *ivbuf = 0; 
		Py_ssize_t inputlen, keylen, ivlen;

	    AES_KEY *aeskey = (AES_KEY *)PyMem_Malloc(sizeof(AES_KEY));
		if (aeskey == 0)
		{
			PyErr_SetString(PyExc_MemoryError, "Insufficient memory for AES key.");
			return 0;
		}
		
		if (PyBytes_Check(input) && PyBytes_Check(key) && PyBytes_Check(iv))
		{
			inputlen =  PyBytes_Size(input);
			keylen = PyBytes_Size(key);
			ivlen = PyBytes_Size(iv);
			inputbuf = (unsigned char*)PyBytes_AsString(input);
			keybuf = (unsigned char*)PyBytes_AsString(key);
			ivbuf = (unsigned char*)PyBytes_AsString(iv);
		}
		else 
		{
			PyErr_SetString(PyExc_MemoryError, "Type error");
			return 0;
		}
		
		int outlen = inputlen > keylen? inputlen : keylen;
		void* outbuf = PyMem_Malloc(outlen);
		memset(outbuf, 0, outlen);
		if (keylen != 16 && keylen != 24 && keylen != 32)
		{
			PyErr_SetString(PyExc_MemoryError, "Key length error");
			return 0;
		}
		if (outbuf != 0)
		{
			if (enc == AES_ENCRYPT)
			{
				AES_set_encrypt_key((const unsigned char*)keybuf, keylen * 8, aeskey);
				AES_cbc_encrypt((const unsigned char*)inputbuf, (unsigned char*)outbuf, outlen, aeskey, ivbuf, enc);
			}
			else if (enc == AES_DECRYPT)
			{
				AES_set_decrypt_key((const unsigned char*)keybuf, keylen * 8, aeskey);
				AES_cbc_encrypt((const unsigned char*)inputbuf, (unsigned char*)outbuf, outlen, aeskey, ivbuf, enc);
			}
		}
		PyMem_Free((void*)aeskey);
		PyObject* bytes =  PyBytes_FromStringAndSize((const char*)outbuf, outlen);
		PyMem_Free((void*)outbuf);
		return bytes;
	}
};

%}
