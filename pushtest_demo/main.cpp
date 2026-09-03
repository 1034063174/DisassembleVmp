#include <cstdio>
#include <cstdint>

extern "C" void pushtest(void* buf);


 int  forTest(int a ,int  b )
{
     int x = 0 ;
     for (int i = 0; i < a;i++)
     {
        
         x++;

     }
     return  x;

}
int main()
{
    uint8_t buf[16] = {};

    printf("before pushtest\n");
    pushtest(buf);
    forTest(7, 9);
    printf("after pushtest\n");
    printf("buf[0]  = 0x%02X\n",       buf[0]);
    printf("buf[1..4] = 0x%08X\n", *(uint32_t*)(buf + 1));
    return 0;
}
