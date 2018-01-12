%constant int RSA_PKCS1_PADDING = RSA_PKCS1_PADDING;
%constant int RSA_SSLV23_PADDING = RSA_SSLV23_PADDING;
%constant int RSA_NO_PADDING = RSA_NO_PADDING;
%constant int RSA_PKCS1_OAEP_PADDING = RSA_PKCS1_OAEP_PADDING;
%constant int RSA_X931_PADDING = RSA_X931_PADDING;
%constant int RSA_PKCS1_PSS_PADDING = RSA_PKCS1_PSS_PADDING;
%constant int RSA_PKCS1_PADDING_SIZE = RSA_PKCS1_PADDING_SIZE;

%inline %{
	
struct PYRSA
{
	static PyObject* public_encrypt(PyObject* input, PyObject* key, int padding)
	{
		BIO* bio = 0;
		RSA* rsa = 0;
		unsigned char *inputbuf = 0, *keybuf = 0; 
		Py_ssize_t inputlen, keylen;
		
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
		
		bio = BIO_new_mem_buf((const void *)keybuf, keylen);
		PyErr_SetString(PyExc_MemoryError, (char*)keybuf);
		if (bio == 0)
		{
			PyErr_SetString(PyExc_MemoryError, "BIO create error");
			return 0;
		}
		rsa = PEM_read_bio_RSA_PUBKEY(bio, 0, 0, 0);
		if (rsa == 0)
		{
			PyErr_SetString(PyExc_MemoryError, "RSA create error");
			return 0;
		}
		
		int outlen = inputlen > keylen? inputlen : keylen;
		void* outbuf = PyMem_Malloc(outlen);
		memset(outbuf, 0, outlen);
		int ret = RSA_public_encrypt(inputlen, (const unsigned char*)inputbuf, (unsigned char*)outbuf, rsa, padding);
		if (ret == -1)
		{
			PyErr_SetString(PyExc_MemoryError, "RSA encrypt failed");
			return 0;
		}

		PyObject* bytes =  PyBytes_FromStringAndSize((const char*)outbuf, outlen);
		PyMem_Free((void*)outbuf);
		BIO_set_close(bio, BIO_CLOSE);
		BIO_free(bio);
		return bytes;
	}
};

%}
