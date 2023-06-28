// We wrap all important calls to glibc to insure that pointers are checked and unprotected before being used 
// internally in glibc or passed to system calls.
//
// For each pointer argument, we need to check, unprotect, call the glibc function and reprotect.
// If a glibc function calls another nested glibc function, there is no need to do further
// processing, because the arguments should have already been checked and unprotected.

#define _GNU_SOURCE

#include <malloc.h>
#include <string.h>
#include <wchar.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <sched.h>
#include <limits.h>
#include <sys/mman.h>

#include <execinfo.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <libintl.h>
#include <locale.h>
#include "dw-log.h"
#include "dw-protect.h"

// Intercept common glibc functions to check access and remove the protection from pointers. 
// This is essential for system calls because otherwise they will fail.
// It is also useful for utility functions as it can simplify the access check (a single one instead of multiple ones)
// and avoid some functions that may perform tricky pointer arithmetic (e.g. memcpy / memmove)
//
// For now only the unprotect / reprotect is done. Access checks have not been added yet.
//
// Limitations
//
// Only a minimal set of wrappers was implemented, it is far from being complete. 
// The fprintf functions were not wrapped, because it would be very difficult to 
// process the pointers in the variable list of arguments that follows the format.
// Moreover, some of the wrappers are incomplete. For instance, for the execvpe and 
// similar functions, the argv and envp arrays are unprotected, but not the pointers
// contained within. This would require allocating a new array where to copy the unprotected
// pointers.

// Check that we can get the desired symbol
void *dlsym_check(void *restrict handle, const char *restrict symbol) {
    void *ret = dlsym(handle, symbol);
    if(ret == NULL) dw_log(WARNING, WRAP, "Symbol %s not found\n", symbol);
    return ret;
}

// Declare all the pointers to the original libc functions

static int (*libc_open)(const char *pathname, int flags, ...);
static int (*libc_openat)(int dirfd, const char *pathname, int flags, ...);
// static int (*libc_openat2)(int dirfd, const char *pathname, const struct open_how *how, size_t size);
static int (*libc_creat)(const char *pathname, mode_t mode);
static int (*libc_access)(const char *pathname, int mode);
static char* (*libc_getcwd)(char *buf, size_t size);
static ssize_t (*libc_getrandom)(void *buf, size_t buflen, unsigned int flags);
static int (*libc_stat)(const char *restrict pathname, struct stat *restrict statbuf);
static int (*libc_fstat)(int fd, struct stat *statbuf);
static int (*libc_lstat)(const char *restrict pathname, struct stat *restrict statbuf);
static int (*libc_fstatat)(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags);
static ssize_t (*libc_pread)(int fd, void *buf, size_t count, off_t offset);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count, off_t offset);
static ssize_t (*libc_read)(int fd, void *buf, size_t count);
extern ssize_t __read(int fd, void *buf, size_t count);
static ssize_t (*libc_write)(int fd, const void *buf, size_t count);
extern ssize_t libc_real_write(int fd, const void *buf, size_t count);
static int (*libc_statfs)(const char *path, struct statfs *buf);
static int (*libc_fstatfs)(int fd, struct statfs *buf);
static ssize_t (*libc_getdents64)(int fd, void *dirp, size_t count);
static DIR* (*libc_opendir)(const char *name);
static int (*libc_bcmp)(const void *s1, const void *s2, size_t n);
static void (*libc_bcopy)(const void *src, void *dest, size_t n);
static void (*libc_bzero)(void *s, size_t n);
static void* (*libc_memccpy)(void *dest, const void *src, int c, size_t n);
static void* (*libc_memchr)(const void *s, int c, size_t n);
static int (*libc_memcmp)(const void *s1, const void *s2, size_t n);
static void* (*libc_memcpy)(void *dest, const void *src, size_t n);
static void* (*libc_memfrob)(void *s, size_t n);
static void* (*libc_memmem)(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
static void* (*libc_memmove)(void *dest, const void *src, size_t n);
static void* (*libc_mempcpy)(void *restrict dest, const void *restrict src, size_t n);
static void* (*libc_memset)(void *s, int c, size_t n);
static char* (*libc_strcpy)(char *restrict dest, const char *src);
static char* (*libc_strncpy)(char *restrict dest, const char *restrict src, size_t n);
static wchar_t* (*libc_wmemmove)(wchar_t *dest, const wchar_t *src, size_t n);
static wchar_t* (*libc_wmempcpy)(wchar_t *restrict dest, const wchar_t *restrict src, size_t n);
static wchar_t* (*libc_wmemcpy)(wchar_t *restrict dest, const wchar_t *restrict src, size_t n);
static char* (*libc_gettext)(const char * msgid);
static char* (*libc_dgettext)(const char * domainname, const char * msgid);
extern char* __dgettext(const char * domainname, const char * msgid);
// static char* (*libc_dcgettext)(const char * domainname, const char * msgid, int category);
extern char* __dcgettext(const char * domainname, const char * msgid, int category);
static char* (*libc_ngettext)(const char *msgid, const char *msgid_plural, unsigned long int n);
// static char* (*libc_dngettext)(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n);
static char* (*libc_dcngettext)(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category);
static char* (*libc_setlocale)(int category, const char *locale);
static char* (*libc_textdomain)(const char * domainname);
static int (*libc_execve)(const char *pathname, char *const argv[], char *const envp[]);
static int (*libc_execv)(const char *pathname, char *const argv[]);
static int (*libc_execvp)(const char *file, char *const argv[]);
static int (*libc_execvpe)(const char *file, char *const argv[], char *const envp[]);


// Get the address for all the wrapped libc functions. Some of these functions may get called
// very early. Therefore we do check for initialization right before use with the iss() macro.

static int init_stubs = 0;

static void init_syscall_stubs() {
    libc_open = dlsym_check(RTLD_NEXT, "open");
    libc_openat = dlsym_check(RTLD_NEXT, "openat");
//    libc_openat2 = dlsym_check(RTLD_NEXT, "openat2");
    libc_creat = dlsym_check(RTLD_NEXT, "creat");
    libc_access = dlsym_check(RTLD_NEXT, "access");
    libc_getcwd = dlsym_check(RTLD_NEXT, "getcwd");
    libc_getrandom = dlsym_check(RTLD_NEXT, "getrandom");
    libc_stat = dlsym_check(RTLD_NEXT, "stat");
    libc_fstat = dlsym_check(RTLD_NEXT, "fstat");
    libc_lstat = dlsym_check(RTLD_NEXT, "lstat");
    libc_fstatat = dlsym_check(RTLD_NEXT, "fstatat");
    libc_pread = dlsym_check(RTLD_NEXT, "pread");
    libc_pwrite = dlsym_check(RTLD_NEXT, "pwrite");
    libc_read = __read; // dlsym_check(RTLD_NEXT, "read");
    libc_write = dlsym_check(RTLD_NEXT, "write");
    libc_statfs = dlsym_check(RTLD_NEXT, "statfs");
    libc_fstatfs = dlsym_check(RTLD_NEXT, "fstatfs");
    libc_getdents64 = dlsym_check(RTLD_NEXT, "getdents64");
    libc_bcmp = dlsym_check(RTLD_NEXT, "bcmp");
    libc_bcopy = dlsym_check(RTLD_NEXT, "bcopy");
    libc_bzero = dlsym_check(RTLD_NEXT, "bzero");
    libc_memccpy = dlsym_check(RTLD_NEXT, "memccpy");
    libc_memchr = dlsym_check(RTLD_NEXT, "memchr");
    libc_memcmp = dlsym_check(RTLD_NEXT, "memcmp");
    libc_memcpy = dlsym_check(RTLD_NEXT, "memcpy");
    libc_memfrob = dlsym_check(RTLD_NEXT, "memfrob");
    libc_memmem = dlsym_check(RTLD_NEXT, "memmem");
    libc_memmove = dlsym_check(RTLD_NEXT, "memmove");
    libc_mempcpy = dlsym_check(RTLD_NEXT, "mempcpy");
    libc_memset = dlsym_check(RTLD_NEXT, "memset");
    libc_strcpy = dlsym_check(RTLD_NEXT, "strcpy");
    libc_strncpy = dlsym_check(RTLD_NEXT, "strncpy");
    libc_wmemmove = dlsym_check(RTLD_NEXT, "wmemmove");
    libc_wmempcpy = dlsym_check(RTLD_NEXT, "wmempcpy");
    libc_wmemcpy = dlsym_check(RTLD_NEXT, "wmemcpy");
    libc_gettext = dlsym_check(RTLD_NEXT, "gettext");
    libc_dgettext = __dgettext; // dlsym_check(RTLD_NEXT, "dgettext ");
//    libc_dcgettext = __dcgettext; // dlsym_check(RTLD_NEXT, "dcgettext");
    libc_ngettext = dlsym_check(RTLD_NEXT, "ngettext");
//    libc_dngettext = dlsym_check(RTLD_NEXT, "dngettext ");
    libc_dcngettext = dlsym_check(RTLD_NEXT, "dcngettext");
    libc_setlocale = dlsym_check(RTLD_NEXT, "setlocale");
    libc_opendir = dlsym_check(RTLD_NEXT, "opendir");
    libc_textdomain = dlsym_check(RTLD_NEXT, "textdomain");
    libc_execve = dlsym_check(RTLD_NEXT, "execve");
    libc_execv = dlsym_check(RTLD_NEXT, "execv");
    libc_execvp = dlsym_check(RTLD_NEXT, "execvp");
    libc_execvpe = dlsym_check(RTLD_NEXT, "execvpe");
    init_stubs = 1;
}

// Each wrapper will check the pointers provided and untaint them. 
// Each wrapper thus starts with sin() that disables nested pointer tainting
// and initializes the pointers to the wrapped symbols. 
// Upon exit, sout() restores the state of pointer tainting.
// It would be tricky to put the wrapped symbols initialization in
// a "constructor" because some of those wrappers may get called by functions in other
// libraries, before the constructor for this module gets called.

#define sin() bool sin_save = dw_protect_active; dw_protect_active = false; if(!init_stubs) init_syscall_stubs()
#define sout() dw_protect_active = sin_save

// For each tainted pointer passed to a wrapper, we could eventually check if it is accessed properly,
// given the semantics of the function called and the bounds of the pointed object.
// The replacements for libc functions for now simply remove the taint before calling
// the replaced functions. In some cases, the taint must be reapplied. For instance,
// the memccpy function copies a string to a certain character then returns a pointer to
// that character. This pointer may be derived from a tainted pointer and the taint must be
// carried to it from the dest pointer.

// Open can take 2 or 3 arguments, we handle it just like glibc does it internally.
int open(const char *pathname, int flags, ...) { 
    sin(); 
    mode_t mode = 0; 
    if(__OPEN_NEEDS_MODE(flags)) {
        va_list arg; 
        va_start(arg, flags); 
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }
    int ret = libc_open(dw_unprotect((void *)pathname), flags, mode);
    dw_reprotect((void *)pathname); sout(); return ret;
}

int openat(int dirfd, const char *pathname, int flags, ...) { 
    sin(); 
    mode_t mode = 0; 
    if(__OPEN_NEEDS_MODE(flags)) {
        va_list arg; 
        va_start(arg, flags); 
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }
    int ret = libc_openat(dirfd, dw_unprotect((void *)pathname), flags, mode);
    dw_reprotect((void *)pathname); sout(); return ret;
}

// int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size) { sin(); return libc_openat2(dirfd, dw_unprotect(pathname), how, size); }
int creat(const char *pathname, mode_t mode) { sin(); int ret = libc_creat(dw_unprotect((void *)pathname), mode); dw_reprotect((void *)pathname); sout(); return ret; }
int access(const char *pathname, int mode) { sin(); int ret = libc_access(dw_unprotect((void *)pathname), mode); dw_reprotect((void *)pathname); sout(); return ret; }
char *getcwd(char *buf, size_t size) { sin(); char *ret = libc_getcwd(dw_unprotect((void *)buf), size); dw_reprotect((void *)buf); sout(); if(ret == dw_untaint(buf)) return buf; return ret; }
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) { sin(); ssize_t ret = libc_getrandom(dw_unprotect(buf), buflen, flags); dw_reprotect(buf); sout(); return ret; }
int stat(const char *restrict pathname, struct stat *restrict statbuf) { sin(); int ret = libc_stat(dw_unprotect((void *)pathname), (struct stat *)dw_unprotect((void *)statbuf)); dw_reprotect((void *)pathname); dw_reprotect((void *)statbuf); sout(); return ret; }
int fstat(int fd, struct stat *statbuf) { sin(); int ret = libc_fstat(fd, (struct stat *)dw_unprotect(statbuf)); dw_reprotect(statbuf); sout(); return ret; }
int lstat(const char *restrict pathname, struct stat *restrict statbuf) { sin(); int ret = libc_lstat(dw_unprotect((void *)pathname), (struct stat *)dw_unprotect((void *)statbuf)); dw_reprotect((void *)pathname); dw_reprotect((void *)statbuf); sout(); return ret; }
int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags) { sin(); int ret = libc_fstatat(dirfd, dw_unprotect((void *)pathname), (struct stat *)dw_unprotect((void *)statbuf), flags); dw_reprotect((void *)pathname); dw_reprotect((void *)statbuf); sout(); return ret; }
ssize_t pread(int fd, void *buf, size_t count, off_t offset) { sin(); ssize_t ret = libc_pread(fd, dw_unprotect(buf), count, offset); dw_reprotect(buf); sout(); return ret; }
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) { sin(); ssize_t ret = libc_pwrite(fd, (const void *)dw_unprotect(buf), count, offset); dw_reprotect(buf); sout(); return ret; }
ssize_t read(int fd, void *buf, size_t count) { sin(); ssize_t ret = libc_read(fd, dw_unprotect(buf), count); dw_reprotect(buf); sout(); return ret; }
ssize_t write(int fd, const void *buf, size_t count) { sin(); ssize_t ret = libc_write(fd, (const void *)dw_unprotect(buf), count); dw_reprotect(buf); sout(); return ret; }
int statfs(const char *path, struct statfs *buf) { sin(); int ret = libc_statfs(dw_unprotect((void *)path), (struct statfs *)dw_unprotect((void *)buf)); dw_reprotect((void *)path); dw_reprotect((void *)buf); sout(); return ret; }
int fstatfs(int fd, struct statfs *buf) { sin(); int ret = libc_fstatfs(fd, (struct statfs *)dw_unprotect((void *)buf)); dw_reprotect((void *)buf); sout(); return ret; }
ssize_t getdents64(int fd, void *dirp, size_t count) { sin(); ssize_t ret = libc_getdents64(fd, dw_unprotect(dirp), count); dw_reprotect(dirp); sout(); return ret; }
DIR *opendir(const char *name) { sin(); DIR *ret = libc_opendir(dw_unprotect(name)); dw_reprotect(name); sout(); return ret; }
int bcmp(const void *s1, const void *s2, size_t n) { sin(); int ret = libc_bcmp((const void *)dw_unprotect(s1), (const void *)dw_unprotect(s2), n); dw_reprotect(s1); dw_reprotect(s2); sout(); return ret; }
void bcopy(const void *src, void *dest, size_t n) { sin(); libc_bcopy((const void *)dw_unprotect(src), (void *)dw_unprotect(dest), n); dw_reprotect(src); dw_reprotect(dest); sout(); }
void bzero(void *s, size_t n) { sin(); libc_bzero((void *)dw_unprotect(s), n); dw_reprotect(s); sout(); }

void *memccpy(void *dest, const void *src, int c, size_t n) { 
    sin(); 
    void *ret = libc_memccpy((void *)dw_unprotect(dest), (const void *)dw_unprotect(src), c, n);
    dw_reprotect(dest);
    dw_reprotect(src);
    sout();
    if(ret == NULL) return ret;
    return (void *)dw_retaint(ret, dest);
}

void *memchr(const void *s, int c, size_t n) { 
    sin(); 
    void *ret = libc_memchr((const void *)dw_unprotect(s), c, n);
    dw_reprotect(s);
    sout();
    if(ret == NULL) return ret;
    return (void *)dw_retaint(ret, s);
}

int memcmp(const void *s1, const void *s2, size_t n) { sin(); int ret = libc_memcmp((const void *)dw_unprotect(s1), (const void *)dw_unprotect(s2), n); dw_reprotect(s1); dw_reprotect(s2); sout(); return ret; }
void *memcpy(void *dest, const void *src, size_t n) { sin(); libc_memcpy((void *)dw_unprotect(dest), (const void *)dw_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
// void *memfrob(void *s, size_t n) { sin(); return libc_memfrob(void *s, size_t n); }

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) { 
    sin();
    void *ret = libc_memmem((const void *)dw_unprotect(haystack), haystacklen, (const void *)dw_unprotect(needle), needlelen); 
    dw_reprotect(haystack); dw_reprotect(needle);
    sout();
    if(ret == NULL) return ret;
    return (void *)dw_retaint(ret, haystack);
}

void *memmove(void *dest, const void *src, size_t n) { sin(); libc_memmove((void *)dw_unprotect(dest), (void *)dw_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
void *mempcpy(void *restrict dest, const void *restrict src, size_t n) { sin(); libc_mempcpy((void *)dw_unprotect(dest), (void *)dw_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
void *memset(void *s, int c, size_t n) { sin(); libc_memset((void *)dw_unprotect(s), c, n); dw_reprotect(s); sout(); return s; }
char *strcpy(char *restrict dest, const char *src) { sin(); libc_strcpy(dw_unprotect(dest), dw_unprotect(src)); dw_reprotect(dest); dw_reprotect(src); sout(); return dest;}
char *strncpy(char *restrict dest, const char *restrict src, size_t n) { sin(); libc_strncpy(dw_unprotect(dest), dw_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
wchar_t *wmemmove(wchar_t *dest, const wchar_t *src, size_t n) { sin(); libc_wmemmove((wchar_t *)dw_unprotect(dest), (wchar_t *)dw_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }

wchar_t *wmempcpy(wchar_t *restrict dest, const wchar_t *restrict src, size_t n) { 
    sin(); 
    wchar_t *ret = libc_wmempcpy((wchar_t *)dw_unprotect(dest), (wchar_t *)dw_unprotect(src), n);
    dw_reprotect(dest); dw_reprotect(src);
    sout(); return (wchar_t *)dw_retaint(ret, dest);
}

wchar_t *wmemcpy(wchar_t *restrict dest, const wchar_t *restrict src, size_t n) { sin(); libc_wmemcpy((wchar_t *)dw_unprotect(dest), (wchar_t *)dw_unprotect(src), n); dw_reprotect(dest); dw_reprotect(src); sout(); return dest; }
char *gettext (const char * msgid) { sin(); char *ret = libc_gettext(dw_unprotect(msgid)); dw_reprotect(msgid); sout(); if(ret == dw_untaint(msgid)) return (char *)msgid; else return ret; }
char *dgettext (const char * domainname, const char * msgid) { sin(); char *ret = libc_dgettext (dw_unprotect(domainname), dw_unprotect(msgid)); dw_reprotect(domainname); dw_reprotect(msgid); sout(); if(ret == dw_untaint(msgid)) return (char *)msgid; else return ret; }
char *dcgettext (const char * domainname, const char * msgid, int category) { sin(); char *ret = __dcgettext (dw_unprotect(domainname), dw_unprotect(msgid), category); dw_reprotect(domainname); dw_reprotect(msgid); sout(); if(ret == dw_untaint(msgid)) return (char *)msgid; else return ret; }
char *ngettext(const char *msgid, const char *msgid_plural, unsigned long int n) { sin(); char *ret = libc_ngettext(dw_unprotect(msgid), dw_unprotect(msgid_plural), n); dw_reprotect(msgid); dw_reprotect(msgid_plural); sout(); if(ret == dw_untaint(msgid)) return (char *)msgid; else if(ret == dw_untaint(msgid_plural)) return (char *)msgid_plural; else return ret; } 
// char *dngettext(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n) { sin(); char *ret = libc_dngettext(dw_unprotect(domainname), dw_unprotect(msgid), dw_unprotect(msgid_plural), n); dw_reprotect(domainname); dw_reprotect(msgid); dw_reprotect(msgid_plural); sout(); if(ret == dw_untaint(msgid)) return (char *)msgid; else if(ret == dw_untaint(msgid_plural)) return (char *)msgid_plural; else return ret; }
char *dcngettext(const char *domainname, const char *msgid, const char *msgid_plural, unsigned long int n, int category) { sin(); char *ret = libc_dcngettext(dw_unprotect(domainname), dw_unprotect(msgid), dw_unprotect(msgid_plural), n, category); dw_reprotect(domainname); dw_reprotect(msgid); dw_reprotect(msgid_plural); sout(); if(ret == dw_untaint(msgid)) return (char *)msgid; else if(ret == dw_untaint(msgid_plural)) return (char *)msgid_plural; else return ret; }
char *setlocale(int category, const char *locale) { sin(); char *ret = libc_setlocale(category, dw_unprotect(locale)); dw_reprotect(locale); sout(); return ret; }
char *textdomain(const char * domainname) { sin(); char *ret = libc_textdomain(dw_unprotect(domainname)); dw_reprotect(domainname); sout(); return ret; }
int execve(const char *pathname, char *const argv[], char *const envp[]) { sin(); int ret = libc_execve(dw_unprotect(pathname), dw_unprotect(argv), dw_unprotect(envp)); dw_reprotect(pathname); dw_reprotect(argv); dw_reprotect(envp); sout(); return ret; }
int execv(const char *pathname, char *const argv[]) { sin(); int ret = libc_execv(dw_unprotect(pathname), dw_unprotect(argv)); dw_reprotect(pathname); dw_reprotect(argv); sout(); return ret; }
int execvp(const char *file, char *const argv[]) { sin(); int ret = libc_execvp(dw_unprotect(file), dw_unprotect(argv)); dw_reprotect(file); dw_reprotect(argv); sout(); return ret; }
int execvpe(const char *file, char *const argv[], char *const envp[]) { sin(); int ret = libc_execvpe(dw_unprotect(file), dw_unprotect(argv), dw_unprotect(envp)); dw_reprotect(file); dw_reprotect(argv); dw_reprotect(envp); sout(); return ret; }



