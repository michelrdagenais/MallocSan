
#define _GNU_SOURCE

#include "dw-disassembly.h"
#include "dw-log.h"
#include "dw-protect.h"
#include <capstone/capstone.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <string.h>
#include <olx/olx.h>

#define MAX_EPILOGUE_SIZE 40

// A simple mmap allocator to provide libolx with chunks of executable memory.
// It is not thread safe and no free is provided.

static void
    *alloc_reserve_current = NULL,
    *alloc_reserve_end = NULL;

static size_t alloc_chunk_size = 2 * PAGE_SIZE;

static void *alloc_olx(size_t *size)
{
    size_t actual_size = *size;
    if(actual_size % 64) actual_size = ((actual_size >> 6) + 1) << 6;
    *size = actual_size;
    
    if(alloc_reserve_current == NULL || alloc_reserve_current + actual_size > alloc_reserve_end) {
        alloc_reserve_current = mmap(NULL, alloc_chunk_size, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if(alloc_reserve_current == MAP_FAILED) dw_log(ERROR, DISASSEMBLY, "Cannot allocate memory for OLX buffers\n");
        alloc_reserve_end = alloc_reserve_current + alloc_chunk_size;
        if(actual_size > alloc_chunk_size) dw_log(ERROR, DISASSEMBLY, "OLX buffer allocation request too large\n");
    }
    void *ret = alloc_reserve_current;
    alloc_reserve_current += actual_size;
    return ret;
}

// For each register than we may encounter in a memory access, we have the name
// and the machine code epilogue, in binary, to retaint the pointer as needed.
//
// The entries are in the order of the index in the mcontext_t structure
// where the registers are saved upon entry in a signal handler.
//
// enum {REG_R8 = 0, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, 
// REG_RDI, REG_RSI, REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX, REG_RSP,
// (those extra registers are in mcontext_t but not used in memory accesses)
// REG_RIP, REG_EFL, REG_CSGSFS, REG_ERR, REG_TRAPNO, REG_OLDMASK, REG_CR2}

struct register_entry {
    char *name;
    unsigned epilogue_size;
    uint8_t epilogue[17];
    bool is_greg;
};

// The epilogue needs to retaint the pointer contained in the register.
// For this test, we just put back 0x0001 in the unused MS bytes.
// If the taint was an object ID, we would save it on the stack
// and the epilogue would have to pop it and put it back as taint
//
// Ideally, the epilogue should not affect any flag or use other registers.
// Otherwise, it would have to save and restore them.
// The following sequence should do the trick to add 0x0001 (shown for r8)
//
//    rorxq   $48, %r8, %r8
//    leaq    0x1(%r8), %r8
//    rorxq   $16, %r8, %r8

struct register_entry reg_table[] = {
    {"r8", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xc0, 0x30, 0x4d, 0x8d, 0x40, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xc0, 0x10, 0x00}, true},
    {"r9", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xc9, 0x30, 0x4d, 0x8d, 0x49, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xc9, 0x10, 0x00}, true},
    {"r10", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xd2, 0x30, 0x4d, 0x8d, 0x52, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xd2, 0x10, 0x00}, true},
    {"r11", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xdb, 0x30, 0x4d, 0x8d, 0x5b, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xdb, 0x10, 0x00}, true},
    {"r12", 17, {0xc4, 0x43, 0xfb, 0xf0, 0xe4, 0x30, 0x4d, 0x8d, 0x64, 0x24, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xe4, 0x10}, true},
    {"r13", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xed, 0x30, 0x4d, 0x8d, 0x6d, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xed, 0x10, 0x00}, true},
    {"r14", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xf6, 0x30, 0x4d, 0x8d, 0x76, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xf6, 0x10, 0x00}, true},
    {"r15", 16, {0xc4, 0x43, 0xfb, 0xf0, 0xff, 0x30, 0x4d, 0x8d, 0x7f, 0x01, 0xc4, 0x43, 0xfb, 0xf0, 0xff, 0x10, 0x00}, true},
    {"rdi", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xff, 0x30, 0x48, 0x8d, 0x7f, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xff, 0x10, 0x00}, true},
    {"rsi", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xf6, 0x30, 0x48, 0x8d, 0x76, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xf6, 0x10, 0x00}, true},
    {"rbp", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xed, 0x30, 0x48, 0x8d, 0x6d, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xed, 0x10, 0x00}, true},
    {"rbx", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xdb, 0x30, 0x48, 0x8d, 0x5b, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xdb, 0x10, 0x00}, true},
    {"rdx", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xd2, 0x30, 0x48, 0x8d, 0x52, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xd2, 0x10, 0x00}, true},
    {"rax", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xc0, 0x30, 0x48, 0x8d, 0x40, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xc0, 0x10, 0x00}, true},
    {"rcx", 16, {0xc4, 0xe3, 0xfb, 0xf0, 0xc9, 0x30, 0x48, 0x8d, 0x49, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xc9, 0x10, 0x00}, true},
    {"rsp", 17, {0xc4, 0xe3, 0xfb, 0xf0, 0xe4, 0x30, 0x48, 0x8d, 0x64, 0x24, 0x01, 0xc4, 0xe3, 0xfb, 0xf0, 0xe4, 0x10}, true}
};

// Map the capstone register identifiers to libpatch gregs context.
// -1 for register not used, -2 for non general purpose register 

static int
cap_to_patch_ctx(unsigned reg) 
{
    int ret = -2;
    switch(reg) {
        case X86_REG_INVALID:  ret = -1; break;
        case X86_REG_RAX: ret = PATCH_X86_64_RAX; break;
        case X86_REG_RBP: ret = PATCH_X86_64_RBP; break;
        case X86_REG_RBX: ret = PATCH_X86_64_RBX; break;
        case X86_REG_RCX: ret = PATCH_X86_64_RCX; break;
        case X86_REG_RDI: ret = PATCH_X86_64_RDI; break;
        case X86_REG_RDX: ret = PATCH_X86_64_RDX; break;
        case X86_REG_RSI: ret = PATCH_X86_64_RSI; break;
        case X86_REG_R8: ret = PATCH_X86_64_R8; break;
        case X86_REG_R9: ret = PATCH_X86_64_R9; break;
        case X86_REG_R10: ret = PATCH_X86_64_R10; break;
        case X86_REG_R11: ret = PATCH_X86_64_R11; break;
        case X86_REG_R12: ret = PATCH_X86_64_R12; break;
        case X86_REG_R13: ret = PATCH_X86_64_R13; break;
        case X86_REG_R14: ret = PATCH_X86_64_R14; break;
        case X86_REG_R15: ret = PATCH_X86_64_R15; break;
    }
    return ret;
}

// Map the capstone register identifiers to Linux mcontext_t ones
// -1 for register not used, -2 for non general purpose register 

static int
cap_to_mctx(unsigned reg) 
{
    int ret = -2;
    switch(reg) {
        case X86_REG_INVALID:  ret = -1; break;
        case X86_REG_RAX: ret = REG_RAX; break;
        case X86_REG_RBP: ret = REG_RBP; break;
        case X86_REG_RBX: ret = REG_RBX; break;
        case X86_REG_RCX: ret = REG_RCX; break;
        case X86_REG_RDI: ret = REG_RDI; break;
        case X86_REG_RDX: ret = REG_RDX; break;
        case X86_REG_RSI: ret = REG_RSI; break;
        case X86_REG_RSP: ret = REG_RSP; break;
        case X86_REG_R8: ret = REG_R8; break;
        case X86_REG_R9: ret = REG_R9; break;
        case X86_REG_R10: ret = REG_R10; break;
        case X86_REG_R11: ret = REG_R11; break;
        case X86_REG_R12: ret = REG_R12; break;
        case X86_REG_R13: ret = REG_R13; break;
        case X86_REG_R14: ret = REG_R14; break;
        case X86_REG_R15: ret = REG_R15; break;
    }
    return ret;
}

/* Names and values for registers used in the Capstone disassembly library

typedef enum x86_reg {
        X86_REG_INVALID = 0,
        X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_BH, X86_REG_BL, // 1-5
        X86_REG_BP, X86_REG_BPL, X86_REG_BX, X86_REG_CH, X86_REG_CL, // 6-10
        X86_REG_CS, X86_REG_CX, X86_REG_DH, X86_REG_DI, X86_REG_DIL, // 11-15
        X86_REG_DL, X86_REG_DS, X86_REG_DX, X86_REG_EAX, X86_REG_EBP, // 16-20
        X86_REG_EBX, X86_REG_ECX, X86_REG_EDI, X86_REG_EDX, X86_REG_EFLAGS, // 21-25
        X86_REG_EIP, X86_REG_EIZ, X86_REG_ES, X86_REG_ESI, X86_REG_ESP, // 26-30
        X86_REG_FPSW, X86_REG_FS, X86_REG_GS, X86_REG_IP, X86_REG_RAX, // 31-35
        X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI, X86_REG_RDX, // 36-40
        X86_REG_RIP, X86_REG_RIZ, X86_REG_RSI, X86_REG_RSP, X86_REG_SI, // 41-45
        X86_REG_SIL, X86_REG_SP, X86_REG_SPL, X86_REG_SS, X86_REG_CR0, // 46-50
        X86_REG_CR1, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR5, // 51-55
        X86_REG_CR6, X86_REG_CR7, X86_REG_CR8, X86_REG_CR9, X86_REG_CR10, // 56-60
        X86_REG_CR11, X86_REG_CR12, X86_REG_CR13, X86_REG_CR14, X86_REG_CR15, // 61-65
        X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3, X86_REG_DR4, // 66-70
        X86_REG_DR5, X86_REG_DR6, X86_REG_DR7, X86_REG_DR8, X86_REG_DR9, // 71-75
        X86_REG_DR10, X86_REG_DR11, X86_REG_DR12, X86_REG_DR13, X86_REG_DR14, // 76-80
        X86_REG_DR15, X86_REG_FP0, X86_REG_FP1, X86_REG_FP2, X86_REG_FP3, // 81-85
        X86_REG_FP4, X86_REG_FP5, X86_REG_FP6, X86_REG_FP7, X86_REG_K0, // 86-90
        X86_REG_K1, X86_REG_K2, X86_REG_K3, X86_REG_K4, X86_REG_K5, // 91-95
        X86_REG_K6, X86_REG_K7, X86_REG_MM0, X86_REG_MM1, X86_REG_MM2, // 96-100
        X86_REG_MM3, X86_REG_MM4, X86_REG_MM5, X86_REG_MM6, X86_REG_MM7, // 101-105
        X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11, X86_REG_R12, // 106-110
        X86_REG_R13, X86_REG_R14, X86_REG_R15, X86_REG_ST0, X86_REG_ST1, // 111-115
        X86_REG_ST2, X86_REG_ST3, X86_REG_ST4, X86_REG_ST5, X86_REG_ST6, // 116-120
        X86_REG_ST7, X86_REG_XMM0, X86_REG_XMM1, X86_REG_XMM2, X86_REG_XMM3, // 121-125
        X86_REG_XMM4, X86_REG_XMM5, X86_REG_XMM6, X86_REG_XMM7, X86_REG_XMM8, // 125-130
        X86_REG_XMM9, X86_REG_XMM10, X86_REG_XMM11, X86_REG_XMM12, X86_REG_XMM13, // 131-135
        X86_REG_XMM14, X86_REG_XMM15, X86_REG_XMM16, X86_REG_XMM17, X86_REG_XMM18, // 136-140
        X86_REG_XMM19, X86_REG_XMM20, X86_REG_XMM21, X86_REG_XMM22, X86_REG_XMM23, // 141-145
        X86_REG_XMM24, X86_REG_XMM25, X86_REG_XMM26, X86_REG_XMM27, X86_REG_XMM28, // 146-150
        X86_REG_XMM29, X86_REG_XMM30, X86_REG_XMM31, X86_REG_YMM0, X86_REG_YMM1, // 151-155
        X86_REG_YMM2, X86_REG_YMM3, X86_REG_YMM4, X86_REG_YMM5, X86_REG_YMM6, // 156-160
        X86_REG_YMM7, X86_REG_YMM8, X86_REG_YMM9, X86_REG_YMM10, X86_REG_YMM11, // 161-165
        X86_REG_YMM12, X86_REG_YMM13, X86_REG_YMM14, X86_REG_YMM15, X86_REG_YMM16, // 166-170
        X86_REG_YMM17, X86_REG_YMM18, X86_REG_YMM19, X86_REG_YMM20, X86_REG_YMM21, // 171-175
        X86_REG_YMM22, X86_REG_YMM23, X86_REG_YMM24, X86_REG_YMM25, X86_REG_YMM26, // 176-180
        X86_REG_YMM27, X86_REG_YMM28, X86_REG_YMM29, X86_REG_YMM30, X86_REG_YMM31, // 181-185
        X86_REG_ZMM0, X86_REG_ZMM1, X86_REG_ZMM2, X86_REG_ZMM3, X86_REG_ZMM4, // 186-190
        X86_REG_ZMM5, X86_REG_ZMM6, X86_REG_ZMM7, X86_REG_ZMM8, X86_REG_ZMM9, // 191-195
        X86_REG_ZMM10, X86_REG_ZMM11, X86_REG_ZMM12, X86_REG_ZMM13, X86_REG_ZMM14, // 195-200
        X86_REG_ZMM15, X86_REG_ZMM16, X86_REG_ZMM17, X86_REG_ZMM18, X86_REG_ZMM19, // 201-205
        X86_REG_ZMM20, X86_REG_ZMM21, X86_REG_ZMM22, X86_REG_ZMM23, X86_REG_ZMM24, // 206-210
        X86_REG_ZMM25, X86_REG_ZMM26, X86_REG_ZMM27, X86_REG_ZMM28, X86_REG_ZMM29, // 211-215
        X86_REG_ZMM30, X86_REG_ZMM31, X86_REG_R8B, X86_REG_R9B, X86_REG_R10B, // 216-220
        X86_REG_R11B, X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B, // 221-225
        X86_REG_R8D, X86_REG_R9D, X86_REG_R10D, X86_REG_R11D, X86_REG_R12D, // 226-230
        X86_REG_R13D, X86_REG_R14D, X86_REG_R15D, X86_REG_R8W, X86_REG_R9W, // 231-235
        X86_REG_R10W, X86_REG_R11W, X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, // 236-240
        X86_REG_R15W, X86_REG_ENDING
} x86_reg;
*/

// When an instruction accesses a protected object, we need to create an entry to
// tell us the affected registers, a buffer to emulate the instruction, and an
// epilogue to reprotect the registers if needed.

struct insn_table {
    size_t size;
    struct insn_entry *entries;
    csh handle;
    cs_insn *insn;
};

// Allocate the instruction hash table and initialize libcapstone

instruction_table*
dw_init_instruction_table(size_t size)
{
    instruction_table *table = malloc(sizeof(instruction_table));
    table->size = 2 * size - 1; // have a hash table about twice as large, and a power of two -1 
    table->entries = calloc(sizeof(struct insn_entry), table->size);

    cs_err csres = cs_open(CS_ARCH_X86, CS_MODE_64, &(table->handle));
    if(csres != CS_ERR_OK) dw_log(ERROR, DISASSEMBLY, "cs_open failed, returned %d\n", csres);
    csres = cs_option(table->handle, CS_OPT_DETAIL, CS_OPT_ON);
    table->insn = cs_malloc(table->handle);    
    olx_init(table->handle, NULL, NULL, NULL, NULL);
    return table;
}

// Deallocate the instruction hash table and close libcapstone

void
dw_fini_instruction_table(instruction_table *table) {
    olx_fini();
    free(table->entries);
    cs_free(table->insn, 1);
    cs_close(&(table->handle));
    free(table);
}

// Get the entry for this instruction address

struct insn_entry*
dw_get_instruction_entry(instruction_table *table, uintptr_t fault)
{
    size_t hash = fault % table->size;
    size_t cursor = hash;

    while((void *)table->entries[cursor].insn != NULL) {
        if(table->entries[cursor].insn == fault) return &(table->entries[cursor]);
        cursor = (cursor + 1) % table->size;
        if(cursor == hash) break;
    }
    return NULL;
}

// Create a new entry for this instruction address

struct insn_entry*
dw_create_instruction_entry(instruction_table *table, uintptr_t fault, uintptr_t *next, mcontext_t *mctx)
{
    size_t hash = fault % table->size;
    size_t cursor = hash;

    while((void *)table->entries[cursor].insn != NULL) {
        if(table->entries[cursor].insn == fault) dw_log(ERROR, DISASSEMBLY, "Trying to add existing instruction in hash table\n"); 
        cursor = (cursor + 1) % table->size;
        if(cursor == hash) dw_log(ERROR, DISASSEMBLY, "Instruction hash table full\n");
    }

    // We insert the new entry at the first empty location following the hash code index
    table->entries[cursor].insn = fault;
    struct insn_entry *entry = &(table->entries[cursor]);
    
    cs_x86 *x86;
    cs_detail *detail;
    size_t sizeds = 100;
    const uint8_t *code = (uint8_t *)fault;
    uint64_t instr_addr = (uint64_t) fault;
    int reg, base, index;
    uintptr_t addr, scale, displacement, base_addr, index_addr;
    unsigned i, j;
    unsigned arg_m = 0, arg_r = 0;
    bool success;
    int error_code;
    
    success = cs_disasm_iter(table->handle, &code , &sizeds, &instr_addr, table->insn);
    error_code = cs_errno(table->handle);
    if(!success) dw_log(ERROR, DISASSEMBLY, "Capstone cannot decode instruction 0x%llx, error %d\n", fault, error_code);
    entry->insn_length = table->insn->size;
    *next = instr_addr;
    snprintf(entry->disasm_insn, sizeof(entry->disasm_insn), "%.8s %.22s", table->insn->mnemonic, table->insn->op_str);
    
    dw_log(INFO, DISASSEMBLY, "Instruction 0x%llx (%d, %d), 0x%lx: %s %s, (%hu)\n", fault, success, 
        error_code, table->insn->address, table->insn->mnemonic, table->insn->op_str, table->insn->size);    

    detail = table->insn->detail;
    x86 = &(detail->x86);

    for (i = 0; i < x86->op_count; i++){
        switch(x86->operands[i].type) {
        
            // We need to know the overwritten registers to avoid retainting them
    	    case X86_OP_REG: 
    	        if(x86->operands[i].access & CS_AC_WRITE && (reg = cap_to_mctx(x86->operands[i].reg)) >= 0) {
    	            if(arg_r >= MAX_REG_ARG) dw_log(ERROR, DISASSEMBLY, "Too many destination register arguments\n");
    	            entry->arg_r[arg_r] = reg;
    	            arg_r++; 
    	        }
    	        dw_log(INFO, DISASSEMBLY, "Register operand %lu, reg %d, access %hhu\n", i, x86->operands[i].reg, x86->operands[i].access);
    	        break;
    	        
            // The memory address is given by base + (index * scale) + displacement
            // Is the base (or even index with scale = 1) tainted? Mark it as protected
            case X86_OP_MEM:
    	        if(arg_m >= MAX_MEM_ARG) dw_log(ERROR, DISASSEMBLY, "Too many memory arguments\n");
    	        
                entry->arg_m[arg_m].base = base = cap_to_mctx(x86->operands[i].mem.base);
                if(base < -1) dw_log(ERROR, DISASSEMBLY, "Base register not general register\n");
                if(base < 0) base_addr = 0; // No base register
                else base_addr = mctx->gregs[base];
                
                entry->arg_m[arg_m].index = index = cap_to_mctx(x86->operands[i].mem.index);
                if(index < -1) dw_log(ERROR, DISASSEMBLY, "Index register not general register\n");
                if(index < 0) index_addr = 0;
                else index_addr = mctx->gregs[index];
                
                entry->arg_m[arg_m].scale = scale = x86->operands[i].mem.scale;
                entry->arg_m[arg_m].displacement = displacement = x86->operands[i].mem.disp;

                addr = base_addr + (index_addr * scale) + displacement;                        
                if(dw_is_protected((void *)base_addr)) {
                    entry->arg_m[arg_m].is_protected = true;
                    entry->arg_m[arg_m].protected_reg = entry->arg_m[arg_m].base;
                    entry->arg_m[arg_m].protected_patch_reg = cap_to_patch_ctx(x86->operands[i].mem.base);
                    if(dw_is_protected((void *)index_addr)) dw_log(ERROR, DISASSEMBLY,"Both base and index registers are protected\n");
                    
                } else if(dw_is_protected((void *)index_addr)) {
                    entry->arg_m[arg_m].is_protected = true;
                    entry->arg_m[arg_m].protected_reg = entry->arg_m[arg_m].index;
                    entry->arg_m[arg_m].protected_patch_reg = cap_to_patch_ctx(x86->operands[i].mem.index);

                } else entry->arg_m[arg_m].is_protected = false;

    	        dw_log(INFO, DISASSEMBLY, 
    	            "Memory operand %lu, segment %d, base %d (0x%llx) + (index %d (0x%llx) x scale %llx) + disp %llx = %llx, access %hhu\n", i, 
    	            x86->operands[i].mem.segment, base, base_addr, index, index_addr, scale, displacement, addr, x86->operands[i].access);
    	            
                arg_m++;
                break;
                
            case X86_OP_IMM:
                dw_log(INFO, DISASSEMBLY, "Immediate operand %lu, value %lu\n", i, x86->operands[i].imm);
                break;
            default:
                dw_log(INFO, DISASSEMBLY, "Invalid operand %lu\n", i);
                break;
        }
    }
    
    // We need to have at least one protected register as memory argument.
    // Otherwise we should not have a segmentation violation.
    entry->nb_arg_m = arg_m;
    entry->nb_arg_r = arg_r;
    unsigned nb_protected = 0;
    
    for(i = 0; i < arg_m; i++) {
        if(entry->arg_m[i].is_protected) {
            nb_protected++;
            
            // We need to retaint the register unless it is overwritten by the instruction
            entry->arg_m[i].reprotect = true;
            for(j = 0; j < arg_r; j++) {
                if(entry->arg_r[j] == entry->arg_m[i].protected_reg) entry->arg_m[i].reprotect = false;
            }
        }
        else entry->arg_m[i].reprotect = false;
    }
    
    if(nb_protected == 0) dw_log(ERROR, DISASSEMBLY,"No protected memory argument but generates a fault\n");
    return entry;
}

// Create an out of line execution (OLX) buffer for this instruction

void
dw_instruction_entry_olx_make(instruction_table *table, struct insn_entry *entry, uintptr_t next)
{
    uint16_t olx_offset;
    size_t olx_size;
    size_t epilogue_size = 0;
    size_t size;
    uint8_t epilogue[MAX_EPILOGUE_SIZE];
    unsigned reg;

    for(int i = 0; i < entry->nb_arg_m; i++) {
        if(entry->arg_m[i].reprotect) {
            reg = entry->arg_m[i].protected_reg;
            size = reg_table[reg].epilogue_size;
            if(epilogue_size + size > MAX_EPILOGUE_SIZE) 
                dw_log(ERROR, DISASSEMBLY, "Epilogue too long\n");
                
            memcpy(epilogue + epilogue_size, reg_table[reg].epilogue, size);
            epilogue_size += size;
        }
    }
    int ret = olx_make(table->insn, 1, NULL, 0, epilogue, epilogue_size, next, alloc_olx, &olx_offset, &(entry->olx_buffer), &olx_size);
    if(ret < 0) dw_log(ERROR, DISASSEMBLY, "Function olx_make did not work\n");
}

// Patch the instruction accessing a protected object and attach a pre and post handler
// to unprotect and reprotect the tainted registers

bool
dw_instruction_entry_patch(struct insn_entry *entry, patch_probe patch_handler)
{
    patch_op op = {
        .type = PATCH_OP_INSTALL,
	.addr.func_sym = NULL,
	.addr.patch_addr = entry->insn,
	.probe = patch_handler,
	.user_data = entry,
	.free_user = free,
    };
    
    int res = patch_queue(PATCH_POST_PROBE, &op);
    if (res == PATCH_OK) {
        patch_result *results;
	size_t results_count;
	patch_commit(&results, &results_count);
	patch_drop_results(results, results_count);
	return true;
    } else return false;
}

// Dump the content of the instruction table, for knowing the
// number of instructions accessing protected objects,
// and the number of hits for each instruction.

void
dw_print_instruction_entries(instruction_table *table, int fd)
{
    struct insn_entry *entry;
    
    for(int i = 0; i < table->size; i++) {
        entry = &(table->entries[i]);
        if((void *)entry->insn != NULL) {
            dw_fprintf(fd, "0x%lx: %9u: %2u: %1u %s\n", entry->insn, entry->hit_count, entry->insn_length, entry->strategy, entry->disasm_insn);    
        }
    }
}

