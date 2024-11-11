#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void syscall_init (void);
void check_address(void *addr);
void sysHalt(void);
void sysExit(int status);
pid_t sysExec(const char *file);
int sysWait(pid_t);
int sysRead(int fd, void *buffer, unsigned length);
int sysWrite(int fd, const void *buffer, unsigned length);
int sysFibo(int n);
int sysMax(int a, int b, int c, int d);

/* prj2 신지원) bool 사용을 위해 추가 */
#include <stdbool.h>

bool sysCreate(const char *file, unsigned size);
bool sysRemove(const char *file);
int sysOpen(const char *file);
void sysClose(int fd);
int sysFilesize(int fd);
void sysSeek(int fd, unsigned position);
unsigned sysTell(int fd);

#endif /* userprog/syscall.h */
