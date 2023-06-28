#ifndef DW_DISASSEMBLY_H
#define DW_DISASSEMBLY_H

#include <ucontext.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <libpatch/patch.h>

#define MAX_MEM_ARG 2
#define MAX_REG_ARG 2

struct insn_table;

typedef struct insn_table instruction_table;

struct memory_arg {
    uintptr_t scale;
    uintptr_t displacement;
    int base;
    int index;
    unsigned protected_patch_reg; // index in patch_probe_context->gregs
    uintptr_t saved_taint;
    unsigned protected_reg; // index in mcontext_t->gregs
    bool is_protected, reprotect;
};

struct insn_entry {
    struct memory_arg arg_m[MAX_MEM_ARG];
    unsigned arg_r[MAX_REG_ARG];
    unsigned nb_arg_m;
    unsigned nb_arg_r;
    uintptr_t insn;
    uintptr_t olx_buffer;
    unsigned hit_count;
    char disasm_insn[32];
    unsigned strategy;
    unsigned insn_length;
};

// For now the instruction table cannot be expanded after initialization
instruction_table*
dw_init_instruction_table(size_t size);

// Free the instruction table. Difficult to be sure that no tainted pointer remains.
void dw_fini_instruction_table(instruction_table *table);

// Check if an entry already exists for that instruction address
struct insn_entry*
dw_get_instruction_entry(instruction_table *table, uintptr_t fault);

// Create a new entry for that instruction address
struct insn_entry*
dw_create_instruction_entry(instruction_table *table, uintptr_t fault, uintptr_t *next, mcontext_t *mctx);

// Add an out of line execution buffer for that entry
void dw_instruction_entry_olx_make(instruction_table *table, struct insn_entry *entry, uintptr_t next);

// If possible, patch the instruction described by that entry and have 
// the specified handler called before and after that instruction
bool dw_instruction_entry_patch(struct insn_entry *entry, patch_probe patch_handler);

// List all the instructions in the table along with their statistics
void dw_print_instruction_entries(instruction_table *table, int fd);

#endif /* DW_DISASSEMBLY_H */
