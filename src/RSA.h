#ifndef __RSA__
#define __RSA__

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

// Base64 URL safe 解码函数
std::string base64UrlDecode(const std::string &input)
{
    std::string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string paddingChar = "=";

    // 调整输入字符串，移除无效字符
    std::string adjustedInput;
    for (char c : input)
    {
        if (base64Chars.find(c) != std::string::npos)
        {
            adjustedInput += c;
        }
    }

    // 计算padding长度
    size_t paddingLength = 0;
    while (adjustedInput.length() % 4 != 0)
    {
        adjustedInput += paddingChar;
        paddingLength++;
    }

    // 解码过程
    std::string decodedOutput;
    std::vector<int> values(4, 0);
    for (size_t i = 0; i < adjustedInput.length(); i += 4)
    {
        for (size_t j = 0; j < 4; j++)
        {
            values[j] = base64Chars.find(adjustedInput[i + j]);
        }

        unsigned char decodedBytes[3];
        decodedBytes[0] = (values[0] << 2) | ((values[1] & 0x30) >> 4);
        decodedBytes[1] = ((values[1] & 0x0F) << 4) | ((values[2] & 0x3C) >> 2);
        decodedBytes[2] = ((values[2] & 0x03) << 6) | values[3];

        for (size_t j = 0; j < 3 - paddingLength; j++)
        {
            decodedOutput += decodedBytes[j];
        }
    }

    return decodedOutput;
}

// Base64 URL safe 编码函数
std::string base64UrlEncode(const std::string &input)
{
    std::string base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string paddingChar = "=";

    // 编码过程
    std::string encodedOutput;
    std::vector<int> values(3, 0);
    size_t inputLength = input.length();
    for (size_t i = 0; i < inputLength; i += 3)
    {
        for (size_t j = 0; j < 3; j++)
        {
            if (i + j < inputLength)
            {
                values[j] = static_cast<unsigned char>(input[i + j]);
            }
            else
            {
                values[j] = 0;
            }
        }

        unsigned char encodedBytes[4];
        encodedBytes[0] = base64Chars[values[0] >> 2];
        encodedBytes[1] = base64Chars[((values[0] & 0x03) << 4) | (values[1] >> 4)];
        encodedBytes[2] = base64Chars[((values[1] & 0x0F) << 2) | (values[2] >> 6)];
        encodedBytes[3] = base64Chars[values[2] & 0x3F];

        // 根据需要添加填充字符
        if (i + 1 >= inputLength)
        {
            encodedBytes[2] = paddingChar[0];
        }
        if (i + 2 >= inputLength)
        {
            encodedBytes[3] = paddingChar[0];
        }

        for (size_t j = 0; j < 4; j++)
        {
            encodedOutput += encodedBytes[j];
        }
    }

    return encodedOutput;
}

std::string base64_encode(const std::string &input)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string output(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return output;
}

std::string base64ToUrlSafe(const std::string &base64)
{
    std::string urlSafeBase64 = base64;

    // 替换一些特殊字符
    std::replace(urlSafeBase64.begin(), urlSafeBase64.end(), '+', '-');
    std::replace(urlSafeBase64.begin(), urlSafeBase64.end(), '/', '_');
    std::replace(urlSafeBase64.begin(), urlSafeBase64.end(), '=', '.');

    return urlSafeBase64;
}

std::string urlSafeToBase64(const std::string &urlSafeBase64)
{
    std::string base64 = urlSafeBase64;

    // 替换一些特殊字符
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');
    std::replace(base64.begin(), base64.end(), '.', '=');

    return base64;
}

std::string rsa_encrypt(const std::string& publicKeyStr, const std::string& plaintext) {
    RSA* rsa = NULL;
    BIO* keyBio = NULL;
    EVP_PKEY* pkey = NULL;
    size_t outputLength = 0;
    unsigned char* outputBuffer = NULL;
    std::string encryptedText;

    // 将公钥字符串加载到BIO中
    keyBio = BIO_new_mem_buf(publicKeyStr.c_str(), -1);

    // 从BIO中读取公钥PEM格式
    rsa = PEM_read_bio_RSA_PUBKEY(keyBio, &rsa, NULL, NULL);

    if (rsa == NULL) {
        std::cout << "无法加载公钥" << std::endl;
        return "";
    }

    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    // 获取加密后数据的长度
    outputLength = EVP_PKEY_size(pkey);
    outputBuffer = new unsigned char[outputLength];

    // 执行加密操作
    int encryptResult = RSA_public_encrypt(plaintext.size(), reinterpret_cast<const unsigned char*>(plaintext.c_str()), outputBuffer, rsa, RSA_PKCS1_PADDING);

    if (encryptResult == -1) {
        std::cout << "加密失败" << std::endl;
        ERR_print_errors_fp(stdout);
        delete[] outputBuffer;
        EVP_PKEY_free(pkey);
        BIO_free_all(keyBio);
        return "";
    }

    // 将加密后的数据转换为Base64编码
    BIO* bio = BIO_new(BIO_f_base64());
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO* bmem = BIO_new(BIO_s_mem());
    bio = BIO_push(bio, bmem);
    BIO_write(bio, outputBuffer, encryptResult);
    BIO_flush(bio);

    char* encodedData;
    long encodedLength = BIO_get_mem_data(bmem, &encodedData);
    encryptedText.assign(encodedData, encodedLength);

    // 清理资源
    delete[] outputBuffer;
    EVP_PKEY_free(pkey);
    BIO_free_all(keyBio);
    BIO_free_all(bio);

    return encryptedText;
}

std::string RsaEncrypt(const std::string& plaintext, const std::string& publicKey)
{
    std::string pk = "-----BEGIN PUBLIC KEY-----\n" + urlSafeToBase64(publicKey) + "\n-----END PUBLIC KEY-----";
    std::string cryptotext = rsa_encrypt(pk, plaintext);
    return base64ToUrlSafe(cryptotext);
}

#endif