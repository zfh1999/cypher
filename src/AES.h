#ifndef __AES__
#define __AES__

#include <iostream>
#include <openssl/aes.h>
#include <iomanip>
#include <string>
#include <cstring>

// 获取输入长度的字母数字组合字符串
std::string generate_random_string(int length)
{
    const char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    std::string random_string;
    random_string.reserve(length);

    srand(time(0));
    for (int i = 0; i < length; i++)
    {
        int index = rand() % strlen(charset);
        random_string += charset[index];
    }

    return random_string;
}

// 字符串转16进制字符串
std::string ByteToHexString(const std::string &byteStr)
{
    std::stringstream ss;
    for (unsigned char c : byteStr)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
    }
    return ss.str();
}

// 16进制字符串转字符串
std::string HexStringToByte(const std::string &hexStr)
{
    std::string result;
    for (size_t i = 0; i < hexStr.size(); i += 2)
    {
        std::string byte = hexStr.substr(i, 2);
        char c = (char)strtol(byte.c_str(), nullptr, 16);
        result.push_back(c);
    }
    return result;
}

// AES加密
std::string aes_encrypt(const std::string &plaintext, const std::string &key)
{
    AES_KEY aes_key;
    if (AES_set_encrypt_key((const unsigned char *)key.c_str(), 128, &aes_key) != 0)
    {
        throw std::runtime_error("Failed to set encryption key");
    }

    size_t padding_size = AES_BLOCK_SIZE - (plaintext.length() % AES_BLOCK_SIZE);
    std::string padded_plaintext = plaintext + std::string(padding_size, static_cast<char>(padding_size));

    std::string ciphertext;
    ciphertext.resize(padded_plaintext.length());

    for (size_t offset = 0; offset < padded_plaintext.length(); offset += AES_BLOCK_SIZE)
    {
        AES_ecb_encrypt(reinterpret_cast<const unsigned char *>(padded_plaintext.c_str() + offset),
                        reinterpret_cast<unsigned char *>(&ciphertext[offset]),
                        &aes_key,
                        AES_ENCRYPT);
    }

    return ByteToHexString(ciphertext);
}

// AES解密
std::string aes_decrypt(const std::string &cipher, const std::string &key)
{
    std::string ciphertext = HexStringToByte(cipher);
    AES_KEY aesKey;
    if (AES_set_decrypt_key((const unsigned char *)key.c_str(), 128, &aesKey) < 0)
    {
        throw std::runtime_error("Failed to set encryption key");
    }

    std::string plaintext;
    plaintext.resize(ciphertext.size());

    for (int i = 0; i < ciphertext.size(); i += AES_BLOCK_SIZE)
    {
        AES_decrypt((const unsigned char *)&ciphertext[i], (unsigned char *)&plaintext[i], &aesKey);
    }

    // Remove padding
    int paddingSize = plaintext[plaintext.size() - 1];
    plaintext.resize(plaintext.size() - paddingSize);

    return plaintext;
}

#endif