#include <string>
#include <stdlib.h>
#include <sstream>

std::string LongToStr(int64_t n)
{
    std::stringstream ss;
    ss << n;
    return ss.str();
}

#ifdef __WIN32__
#include <windows.h>
#include <time.h>

std::string GetMsTimeStr()
{
    time_t tt;
    struct tm *st;
    time(&tt);

    SYSTEMTIME t1;
    GetSystemTime(&t1);

    std::stringstream ss;
    ss << tt << (int)t1.wMilliseconds;
    return ss.str();
}

#elif __linux__
#include <sys/time.h>
#include <unistd.h>

std::string GetMsTimeStr()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    int64_t time = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    return LongToStr(time);
}
#endif
