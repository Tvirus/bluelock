#ifndef _BLUELOCK_H_
#define _BLUELOCK_H_




#ifndef u8
#define u8  unsigned char
#endif
#ifndef s8
#define s8  signed char
#endif

#ifndef u16
#define u16  unsigned short
#endif
#ifndef s16
#define s16  signed short
#endif

#ifndef u32
#define u32  unsigned int
#endif
#ifndef s32
#define s32  signed int
#endif




typedef struct {
    char name[32];
    char mac[24];
    s16 rssi;
}BL_dev_list_t;


extern int BL_get_dev_list(BL_dev_list_t *list, u32 len);
extern int BL_openlock(const char *mac);
extern int BL_poweroff(void);


#endif
