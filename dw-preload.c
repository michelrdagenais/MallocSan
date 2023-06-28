#define _GNU_SOURCE

#include "dw-log.h"
#include "dw-disassembly.h"
#include "dw-protect.h"
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <limits.h>
#include <ucontext.h>
#include <strings.h>

static size_t nb_insn_olx_entries = 10000;

enum dw_strategies {DW_SIGSEGV_OLX=0, DW_PATCH};

static enum dw_strategies dw_strategy = DW_SIGSEGV_OLX;

static instruction_table *insn_table;

// Handler executed before and after instructions that possibly access tainted pointers
// when an instruction is "patched" to insert pre and post probes.

static void patch_handler(struct patch_probe_context *ctx, bool post)
{
    struct insn_entry *entry = ctx->user_data;

    // Untaint all possibly tainted memory arguments, save the tainted pointer to retaint afterwards
    if (!post) {
        for(int i = 0; i < entry->nb_arg_m; i++) {
            if(entry->arg_m[i].is_protected) {
                unsigned reg = entry->arg_m[i].protected_patch_reg;
                entry->arg_m[i].saved_taint = ctx->gregs[reg];
                ctx->gregs[reg] = (uint64_t)dw_unprotect((void *)ctx->gregs[reg]);
            }
        }
        entry->hit_count++;
        
    // Retaint the tainted pointers after the access
    } else {
        for(int i = 0; i < entry->nb_arg_m; i++) {
            if(entry->arg_m[i].reprotect) {
                int reg = entry->arg_m[i].protected_patch_reg;
                ctx->gregs[reg] = (uint64_t)dw_retaint((void *)ctx->gregs[reg], (void *)entry->arg_m[i].saved_taint);
            }
        }    
    }
}

// A protected object was presumably accessed, raising a signal (SIGSEGV or SIGBUS)

void signal_protected(int sig, siginfo_t *info, void *context)
{
    struct insn_entry *entry;

    // We should not have any tainted pointer access while in the handler.
    // It is not reentrant and signals are blocked anyway.
    bool save_active = dw_protect_active;
    dw_protect_active = false;

    // Check if we are within wrapped / inactive functions where this signal should not happen
    if(!save_active) dw_log(WARNING, MAIN, "Signal received while within wrappers\n");
    
    // Get the instruction address
    mcontext_t* mctx = &(((ucontext_t*)context)->uc_mcontext);
    uintptr_t fault_insn = mctx->gregs[REG_RIP];
    uintptr_t next_insn;
      
    // Check if it is the first time that we encounter this address
    entry = dw_get_instruction_entry(insn_table, fault_insn);

    // New address, create an entry in the table
    if(entry == NULL) {
        entry = dw_create_instruction_entry(insn_table, fault_insn, &next_insn, mctx);
        dw_log(INFO, MAIN, "Created entry for instruction %llx\n", entry->insn);

        // Here we want to patch all instructions accessing protected pointers
        // If we cannot install the patch, we fall back to the olx buffer strategy
        if(dw_strategy == DW_PATCH) {
            bool success = dw_instruction_entry_patch(entry, patch_handler);
            if(success) {     
                dw_log(INFO, MAIN, "Patched instruction %llx\n", entry->insn);
                entry->strategy = DW_PATCH;
                dw_protect_active = save_active;
                return;
            } else dw_log(WARNING, MAIN, "Patch failed for instruction %llx\n", entry->insn);
        }
        else if(dw_strategy != DW_SIGSEGV_OLX) dw_log(ERROR, MAIN, "Unknown strategy %d\n", dw_strategy);
        
        // Create the out of line execution buffer to make the access and reprotect the object upon each SIGSEGV
        dw_instruction_entry_olx_make(insn_table, entry, next_insn);
        entry->strategy = DW_SIGSEGV_OLX;
    }  

    // We use the OLX buffer, check that the same register is protected, unprotect it,
    // increase the hit count, and jump to the OLX buffer

    for(int i = 0; i < entry->nb_arg_m; i++) {
        if(entry->arg_m[i].is_protected) {
            int reg = entry->arg_m[i].protected_reg;
            if(dw_is_protected((void *)mctx->gregs[reg])) 
                mctx->gregs[reg] = (long long int)dw_unprotect((void *)mctx->gregs[reg]);
            else dw_log(ERROR, MAIN, "Memory argument register is unexpectedly not protected\n");
        }
    }
    entry->hit_count++;
    mctx->gregs[REG_RIP] = entry->olx_buffer;
    dw_protect_active = save_active;
}

// Since this library is activated by LD_PRELOAD, we cannot use the main function argv
// to receive arguments. We use environment variables instead.

// Range of object sizes to protect, by default protect all
static size_t 
  min_protect_size = 0, 
  max_protect_size = ULONG_MAX;

// What objects in sequence to protect, from (first) to (first + max)
// By default protect all

static long unsigned 
  nb_protected = 0, 
  nb_protected_candidates = 0, 
  first_protected = 0, 
  max_nb_protected = ULONG_MAX;
  
static enum dw_log_level log_level = 0;

// Generate a statistics file with instructions hits
static char *stats_file = NULL;

// This is the initialisation function called at preload time
extern void __attribute__((constructor(65535))) 
dw_init()
{
    dw_log(INFO, MAIN, "Starting program dw\n");

    // Get the parameters passed as environment variables
    char *arg = getenv("DW_MIN_SIZE");
    if(arg != NULL) min_protect_size = atol(arg);
    arg = getenv("DW_MAX_SIZE");
    if(arg != NULL) max_protect_size = atol(arg);
    arg = getenv("DW_MAX_NB_PROTECTED");
    if(arg != NULL) max_nb_protected = atol(arg);
    arg = getenv("DW_FIRST_PROTECTED");
    if(arg != NULL) first_protected = atol(arg);
    arg = getenv("DW_INSN_ENTRIES");
    if(arg != NULL) nb_insn_olx_entries = atol(arg);
    arg = getenv("DW_LOG_LEVEL");
    if(arg != NULL) { log_level = atoi(arg); dw_set_log_level(log_level); }
    arg = getenv("DW_STATS_FILE");
    if(arg != NULL) stats_file = arg;
    arg = getenv("DW_STRATEGY");
    if(arg != NULL) dw_strategy = atoi(arg);

    dw_log(INFO, MAIN, "Min protect size %lu, max protect size %lu, max nb protected %lu, first protected %lu, instruction entries %lu\n", 
        min_protect_size, max_protect_size, max_nb_protected, first_protected, nb_insn_olx_entries);
    dw_log(INFO, MAIN, "Log level %d, stats file %s, strategy %d\n", log_level, stats_file, dw_strategy);

    // Initialise the different modules
    insn_table = dw_init_instruction_table(nb_insn_olx_entries);
    if(dw_strategy == DW_PATCH) { 
    	patch_opt options[] = {{.what = PATCH_OPT_FILTER_MODULE_STR, .str  = ".+",},};
      	patch_init(options, sizeof(options) / sizeof(patch_opt));
    }

    // Insert the SIGSEGV signal handler to catch protected pointers   
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigfillset(&sa.sa_mask);
    sa.sa_sigaction = signal_protected;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    
    // start intercepting allocation functions        
    dw_protect_active = true;
}

extern void
__attribute__((destructor)) dw_fini()
{
    // Generate a statistics file
    if(stats_file != NULL) {
        int fd = open(stats_file, O_WRONLY | O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
        if(fd < 0) dw_log(WARNING, MAIN, "Cannot open file '%s' to write statistics\n", stats_file);
        else {
            dw_print_instruction_entries(insn_table, fd);
            close(fd);
        }
    }
    dw_protect_active = false;
    // If there could be remaining tainted pointers, do not free the table
    // dw_fini_instruction_table(insn_table);
    // if(dw_strategy == DW_PATCH) patch_fini();
}

// Filter the objects to be tainted according to size range and
// Rank in the allocation sequence.

static bool 
check_candidate(size_t size)
{
    if(size >= min_protect_size && size <= max_protect_size) {
        nb_protected_candidates++;
        if(nb_protected_candidates > first_protected && nb_protected < max_nb_protected) {
            nb_protected++;
            return true;
        }
    }
    return false;
}

// For now we will not taint objects allocated from libraries,
// and we assume that this starts at that address. We should
// read /proc/self/maps and let the user specify which libraries to
// exclude from tainting allocations.

static void *library_start = (void *)0x700000000000;

static bool
check_caller(void *caller)
{
  return caller < library_start;
}

// Common malloc that checks if the object should be tainted

static void*
malloc2(size_t size, void *caller)
{
    void *ret = NULL;
    bool save_active = dw_protect_active;
    dw_protect_active = false;
    
    if(save_active) {
        if(check_caller(caller)) {
            if(check_candidate(size)) ret = dw_malloc_protect(size);
        }
        else dw_log(WARNING, MAIN, "Not tainting malloc, caller from library\n");
    }
    if(ret == NULL) ret = __libc_malloc(size);
    
    dw_protect_active = save_active;
    dw_log(INFO, MAIN, "Malloc %p, size %lu, nb_candidates %lu\n", ret, size, nb_protected_candidates);
    return ret;
}

// Normal malloc, note the caller and call the common malloc

void*
malloc(size_t size)
{
    return malloc2(size, __builtin_return_address(0));
}

// When we will keep a table of protected objects, we will be able
// to do something smarter here. The problem is that we do not know the size
// of the existing object and we need to copy it to the new...

void*
realloc(void *ptr, size_t size)
{
    void *ret;
    
    ret = __libc_realloc(dw_unprotect(ptr), size);
    ret = dw_retaint(ret, ptr);
    dw_log(INFO, MAIN, "Realloc %p, size %lu\n", ret, size);
    return ret;
}

void
free(void *ptr)
{
    bool save_active = dw_protect_active;
    dw_protect_active = false;

    if(dw_is_protected(ptr)) {
        dw_free_protect(ptr);
    } else {
        __libc_free(ptr);
    }
    dw_protect_active = save_active;
    dw_log(INFO, MAIN, "Free %p\n", ptr);
}

void*
memalign(size_t alignment, size_t size)
{
    void *ret;
    bool save_active = dw_protect_active;
    dw_protect_active = false;
    
    if(save_active && check_candidate(size)) ret = dw_memalign_protect(alignment, size);
    else ret = __libc_memalign(alignment, size);
    
    dw_protect_active = save_active;
    dw_log(INFO, MAIN, "Memalign %p, size %lu, nb_candidates %lu\n", ret, size, nb_protected_candidates);
    return ret;
}

void*
calloc(size_t nmemb, size_t size)
{
    void *ret = malloc2(nmemb * size, __builtin_return_address(0));
    bzero(ret, nmemb * size);
    return ret;
}

