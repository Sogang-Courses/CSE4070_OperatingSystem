#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
/* prj1 신지원)  is_user_vaddr 위해 추가 */
#include "threads/vaddr.h"
/* prj2 신지원)  file 다루기 위해 추가 */
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);
//struct lock file_lock;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void check_address(void *addr)
{
  if (!is_user_vaddr(addr) || is_kernel_vaddr(addr))
    sysExit(-1);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // printf ("system call!\n");
  // thread_exit ();

  /* prj1 신지원) SYS_CALL 설정 */
  int syscallNumber = *(uint32_t *)(f->esp);
    switch (syscallNumber)
    {
      case SYS_HALT:
        {
          /* prj1 신지원)  반환 주소 상관없이 종료 */
          sysHalt();
          break;
        }

      case SYS_EXIT:
        {
          /* prj1 신지원)  반환 주소가 유효한지 체크한 뒤 그 주소로 돌아감 */
          check_address(f->esp + 4);
          int address = *(uint32_t *)(f->esp + 4);
          sysExit(address);
          break;
        }
      
      case SYS_EXEC:
        {
          /* prj1 신지원)  반환 주소가 유효한지 체크한 뒤 전달된 파일 이름의 주소를 저장 */
          check_address(f->esp + 4);
          const char *file = (char *)*(uint32_t *)(f->esp + 4);
          f->eax = sysExec(file);
          break;
        }

      case SYS_WAIT:
        {
          check_address(f->esp + 4);
          pid_t pid = *(uint32_t *)(f->esp + 4);
          f->eax = sysWait(pid);
          break;
        }
      case SYS_READ:
        {
	  check_address(f->esp + 4);
          check_address(f->esp + 8);
          check_address(f->esp + 12);
          
	  int fd = (int)*(uint32_t *)(f->esp + 4);
          void *buf = (void *)*(uint32_t *)(f->esp + 8);
          unsigned size = (unsigned)*(uint32_t *)(f->esp + 12);
          f->eax = sysRead(fd, buf, size);
          break;
        }

      case SYS_WRITE:
        {
	  check_address(f->esp + 4);
          check_address(f->esp + 8);
          check_address(f->esp + 12);

          int fd = (int)*(uint32_t *)(f->esp + 4);
          const void *buf = (void *)*(uint32_t *)(f->esp + 8);
          unsigned size = (unsigned)*(uint32_t *)(f->esp + 12);
          f->eax = sysWrite(fd, buf, size);
          break;
        }

      case SYS_FIBO:
        {
          int num = (int)*(uint32_t *)(f->esp + 4);
          f->eax = sysFibo(num);
          break;
        }

      case SYS_MAX:
        {
          int a = (int)*(uint32_t *)(f->esp + 4);
          int b = (int)*(uint32_t *)(f->esp + 8);
          int c = (int)*(uint32_t *)(f->esp + 12);
          int d = (int)*(uint32_t *)(f->esp + 16);
          f->eax = sysMax(a, b, c, d);
          break;
        }

	/* prj2 신지원) 추가 SYS_CALL 설정 */

      case SYS_CREATE:
	{
	  check_address(f->esp + 4);
	  check_address(f->esp + 8);
	  const char *file = (const char *)*(uint32_t *)(f->esp + 4);
	  unsigned size = (unsigned)*(uint32_t *)(f->esp + 8);
	  f->eax = sysCreate(file, size);
	  break;
	}

      case SYS_REMOVE:
        {
	  check_address(f->esp + 4);
	  const char *file = (const char *)*(uint32_t *)(f->esp + 4);
	  f->eax = sysRemove(file);
          break;
        }

      case SYS_OPEN:
        {
	  check_address(f->esp + 4);
          const char *file = (const char *)*(uint32_t *)(f->esp + 4);
          f->eax = sysOpen(file);
          break;
        }

      case SYS_FILESIZE:
        {
	  check_address(f->esp + 4);
          int fd = (int)*(uint32_t *)(f->esp + 4);
	  f->eax = sysFilesize(fd);
          break;
        }

      case SYS_SEEK:
        {
          check_address(f->esp + 4);
          check_address(f->esp + 8);
          int fd = (int)*(uint32_t *)(f->esp + 4);
	  unsigned position = (unsigned)*(uint32_t *)(f->esp + 8);
          sysSeek(fd, position);
          break;
        }

      case SYS_TELL:
        {
          check_address(f->esp + 4);
          int fd = (int)*(uint32_t *)(f->esp + 4);
          f->eax = sysTell(fd);
          break;
        }

      case SYS_CLOSE:
        {
	  check_address(f->esp + 4);
	  int fd = (int)*(uint32_t *)(f->esp + 4);
	  sysClose(fd);
          break;
        }
    }
}

void sysHalt()
{
  shutdown_power_off();
}

void sysExit (int status)
{
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status = status;
  for (int i = 3; i < 128; i++)
  {
    if (thread_current()->fd[i] != NULL)
      sysClose(i);
  }
  thread_exit();
}

pid_t sysExec(const char *file)
{
  return process_execute(file);
}

int sysWait(pid_t pid)
{
  return process_wait(pid);
}

int sysRead(int fd, void *buf, unsigned size)
{
  check_address(buf);
  if (fd < 0 || fd >= 128) {
    sysExit(-1);
  }
  
  lock_acquire(&file_lock);
  int res=-1;

  if (fd == 0)
  {
    int cnt = 0;
    while (cnt++ < (int)size)
    {
      uint8_t c = input_getc();
      if (c == '\0')
        break;
    }
    res = cnt;
  } else if (fd >= 3 && fd < 128) {
    struct file *file = thread_current()->fd[fd];
    if (!file) {
      sysExit(-1);
    } else {
      res = file_read(file, buf, size);
    }
  }
  
  lock_release(&file_lock);
  return res;
}

int sysWrite(int fd, const void *buf, unsigned size)
{
  check_address(buf);
  if (fd < 0 || fd >= 128) {
    sysExit(-1);
  }

  lock_acquire(&file_lock);
  int res=-1;

  if (fd == 1)
  {
    putbuf((char *)buf, (size_t)size);
    res =  size;
  } else if (fd >= 3 && fd < 128) {
    struct file *file = thread_current()->fd[fd];
    if (!file) {
      sysExit(-1);
    } else {
      res = file_write(file, buf, size);
    }
  }

   lock_release(&file_lock);
   return res;
}

int sysFibo(int n)
{
    if (n <= 1)
        return n;

    int a = 0, b = 1, sum = 0;
    for (int i = 2; i <= n; i++)
    {
        sum = a + b;
        a = b;
        b = sum;
    }

    return b;
}

int sysMax(int a, int b, int c, int d)
{
  int max = (a > b) ? a : b;
  max = (max > c) ? max : c;
  max = (max > d) ? max : d;

  return max;
}

/* prj2 신지원) 추가 SYS_CALL 작동 구현 */

bool sysCreate(const char *file, unsigned size)
{
  if(file == NULL)
    sysExit(-1);
  return filesys_create(file, size);
}

bool sysRemove(const char *file)
{
  if(file == NULL)
    sysExit(-1);
  return filesys_remove(file);
}

int sysOpen(const char *file)
{
  if(file == NULL)
    sysExit(-1);

  lock_acquire(&file_lock);

  struct file *fp = filesys_open(file);
  int res = -1;
  if (fp == NULL)
    res = -1;
  else
  {
    for(int i=3; i<128;i++)
    {
      if(thread_current()->fd[i] == NULL)
      {
	if(!strcmp(thread_current()->name, file))
          file_deny_write(fp);
        thread_current()->fd[i] = fp;
	
	res = i;
	break;
      }
    }
  }

  lock_release(&file_lock);
  return res;
}

int sysFilesize(int fd)
{
  if (thread_current()->fd[fd] == NULL)
    sysExit(-1);
  return file_length(thread_current()->fd[fd]);
}


void sysSeek(int fd, unsigned position)
{
  if (thread_current()->fd[fd] == NULL)
    sysExit(-1);
  file_seek(thread_current()->fd[fd], position);
}

unsigned sysTell(int fd)
{
  if (thread_current()->fd[fd] == NULL)
    sysExit(-1);
  return file_tell(thread_current()->fd[fd]);
}

void sysClose(int fd)
{
  if (thread_current()->fd[fd] == NULL)
    sysExit(-1);
  file_close(thread_current()->fd[fd]);
  thread_current()->fd[fd] = NULL;
}

