#include <cstdio>
#include <cstdint>

extern "C" void pushtest(void* buf);

int main()
{
    uint8_t buf[16] = {};

    printf("before pushtest\n");
    pushtest(buf);
    printf("after pushtest\n");
    printf("buf[0]  = 0x%02X\n",       buf[0]);
    printf("buf[1..4] = 0x%08X\n", *(uint32_t*)(buf + 1));
    return 0;
}
