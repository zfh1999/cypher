#include "curl/curl.h"
#include <string>

#ifndef HTTPS_USE_CURL_HPP
#define HTTPS_USE_CURL_HPP

// curl实现https请求的类
class HttpsUseCurl
{
public:
    static std::string sendGetRequest(const std::string &url)
    {
        std::string result;
        CURL *curl = curl_easy_init();
        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

            curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
        return result;
    }

    static std::string sendPostRequest(const std::string &url, const std::string &data, const std::string &header)
    {
        std::string result;
        CURLcode errcode;
        CURL *curl = curl_easy_init();
        struct curl_slist *headers = NULL;
        if (curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result);

            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, data.length());
            headers = curl_slist_append(headers, "content-type:application/json");
            headers = curl_slist_append(headers, header.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            errcode = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }
        return result;
    }

    static size_t write_data(void *contents, size_t size, size_t nmemb, void *stream)
    {
        std::string *str = (std::string *)stream;
        (*str).append((char *)contents, size * nmemb);
        return size * nmemb;
    }
};

#endif