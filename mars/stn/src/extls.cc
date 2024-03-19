#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include <iostream>
#include <string>
#include <cassert>
using namespace std;

namespace {

void generate_key_pair(string & pub_key, string & priv_key){
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    assert(1==EC_KEY_generate_key(ec_key));
    assert(1==EC_KEY_check_key(ec_key));

    BIO * bio = BIO_new_fp(stdout,0);
    // assert(1==EC_KEY_print(bio, ec_key, 0));
    BIO_free(bio);

    {
        FILE * f = fopen(pub_key.c_str(),"w");
        PEM_write_EC_PUBKEY(f, ec_key);
        //PEM_write_bio_EC_PUBKEY(bio, ec_key);
        fclose(f);
    }

    {
        FILE * f = fopen(priv_key.c_str(),"w");
        PEM_write_ECPrivateKey(f,ec_key, NULL,NULL,0,NULL,NULL);
        //PEM_write_bio_ECPrivateKey(bio,ec_key, NULL,NULL,0,NULL,NULL);
        fclose(f);
    }

    EC_KEY_free(ec_key);
}

void sign_buff(const string & priv_key_file_path, const unsigned char * buff, int buff_len, string & sig){
 
    FILE * f = fopen(priv_key_file_path.c_str(), "r");
    EC_KEY *ec_key = PEM_read_ECPrivateKey(f,NULL,NULL,NULL);
    fclose(f);
    assert(1==EC_KEY_check_key(ec_key));

    EVP_PKEY * key = EVP_PKEY_new();
    assert(1==EVP_PKEY_assign_EC_KEY(key, ec_key));

    EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(key,NULL);
    assert(1==EVP_PKEY_sign_init(key_ctx));
    assert(1==EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256()) );
    size_t sig_len=0;

    assert(1==EVP_PKEY_sign(key_ctx,NULL,&sig_len, buff , buff_len));
    sig.assign(sig_len,0);
    assert(1==EVP_PKEY_sign(key_ctx,(unsigned char *) &sig[0],&sig_len, buff, buff_len));


    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(key);
}

bool verify_sig_of_buff(const string & pub_key_file_path, const unsigned char * buff, size_t buff_len, const string & sig){
    FILE * f = fopen(pub_key_file_path.c_str(), "r");
    EC_KEY *ec_key = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

 
    EVP_PKEY * key = EVP_PKEY_new();
    assert(1==EVP_PKEY_assign_EC_KEY(key, ec_key));

    EVP_PKEY_CTX * key_ctx = EVP_PKEY_CTX_new(key,NULL);

    assert(1==EVP_PKEY_verify_init(key_ctx));
    assert(1==EVP_PKEY_CTX_set_signature_md(key_ctx, EVP_sha256()) );
    size_t sig_len=0;

    const int ret=EVP_PKEY_verify(key_ctx, (unsigned char * )&sig[0],sig.size(), buff , buff_len);

    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_free(key);

    cout<<ret<<endl;
    return ret;
}

enum KeyAgreementMethod {
   KAM_1RTT_ECDHE = 1,
   KAM_1RTT_PSK = 2,
   KAM_0RTT_PSK = 3,
};

enum ExTlsState {
    ETS_INIT = 1,
    ETS_OK = 2,
};

class TTLConnect {
  public:	
    ExTls(const std::string& pub_key_path,
          const std::string& pri_key_path,
          const std::string& static_srv_pub_key_path,
          const std::string& srv_pub_key_path,
          const std::string& server_sign_key_path,
          const std::string& ) {
    }

    void GnerateLocalkeyPair(){
    }

    virtual void Run() = 0;

    std::string Encode(const char* input, size_t input_len) {
	// Output buffer for encrypted data
        unsigned char output[input_len + EVP_CIPHER_CTX_block_size(ctx)];
        int len;

        // Encrypt the data
    	EVP_EncryptUpdate(encrypt_ctx, output, &len, input, input_len);
        int encrypted_len = len;

	// Finalize the encryption
    	EVP_EncryptFinal_ex(encrypt_ctx, output + len, &len);
	return std::stirng(output, encrypted_len + len);
    }

    std::string Decode(const char* encrypted_data, size_t encrypted_len) {
        int len;
	// Output buffer for decrypted data
    	unsigned char decrypted[encrypted_len];

    	// Decrypt the data
    	EVP_DecryptUpdate(decrypt_ctx, decrypted, &len, encrypted, encrypted_len);
    	int decrypted_len = len;

    	// Finalize the decryption
    	EVP_DecryptFinal_ex(decrypt_ctx, decrypted + len, &len);
    	decrypted_len += len;
    }

    bool InitContent() {
    	encrypt_ctx = EVP_CIPHER_CTX_new();
    	EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_256_gcm(), NULL, client_write_key, client_write_IV);

        decrypt_ctx = EVP_CIPHER_CTX_new();
    	EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    }

    void UninitContent() {
        EVP_CIPHER_CTX_free(encrypt_ctx);
        EVP_CIPHER_CTX_free(decrypt_ctx);
    }

  Private:
    std::string client_write_key;
    std::string server_write_key;
    std::string client_write_IV;
    std::string server_write_IV;

    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER_CTX *decrypt_ctx;
}

class ExTls_1RTT_ECDHE {
  public:	
    ExTls(const std::string& pub_key_path,
          const std::string& pri_key_path,
          const std::string& static_srv_pub_key_path,
          const std::string& srv_pub_key_path,
          const std::string& server_sign_key_path,
          const std::string& ) {
    }

    void GnerateLocalkeyPair(string & pub_key, string & priv_key){
    }

    void Run() {
    }
  Private:
}


}


