/*
 * filename: main.cpp
 * Author: Ivan P
 * Date: 03 Sep 2023
 * License: Public Domain
 * Version: PoC, unversioned
 *
 * Description:
 * 	This program restores relocations for BL instructions in a statically linked,
 * 	unstripped(!) vmlinux binary. Currently the program is limited to BL instructions
 * 	in a single function.
 *
 * Included with this source file:
 * 	- `configure` script
 * 	- Makefile.in
 * 	- ELFIO/ library
 * 	- gnu.linkonce.this_module.bin, modinfo.bin, protos.bin -- Raw ELF sections from LKM
 * 	- post-processing.txt - contains objcopy recipies to conver the result to an LKM
 *
 * Dependencies:
 * 	sudo apt install libspdlog-dev
 * 	sudo apt install libfmt-dev
 * 	sudo apt isntall libcapstone-dev
 *
 * Build:
 * 	./configure (this really only checks for dependencies, you can manuall cp Makefile.in Makefile)
 * 	make
 *
 * Run:
 * 	./relocator vmlinux meson_uvm_init
*/ 

#include <iostream>
#include <list>
#define FMT_HEADER_ONLY
#include <fmt/core.h>
#include <fmt/color.h>
#include <fmt/format.h>
#include <elfio/elfio.hpp>
#include <spdlog/spdlog.h>
#include <capstone/capstone.h>

using namespace ELFIO;

#define SYMBOL_ENTRY_SIZE sizeof(Elf64_Sym)

struct Elf64_Sym_xx
{
    Elf_Word      st_name;
    unsigned char st_info;
    unsigned char st_other;
    Elf_Half      st_shndx;
    Elf64_Addr    st_value;
    Elf_Xword     st_size;
};


struct symbol {
	std::string name;
	Elf64_Addr value;
	Elf_Xword size;
	unsigned char type;
	Elf_Half section_index;
	unsigned char bind;
	unsigned char other;
	uint32_t offset; /* offset from the section start */
	uint32_t index;
};

/* Add new relocation section to te binary.
 *
 * This new section will contain relocations for instructions (e.g. BL)
 * in function <targetfn> in section <base_sec>
 *
 * :params
 *   base_sec  Base section that contains <targetfn> and requires new relocations.
 *   targetfn  The name of the function who's instructions need to be patched (e.g. BL printk)
 *             We only use this parameter to name the new relocation table.
 *   reader    ELFIO reader object.
*/
section* add_new_rela_sec(section* base_sec, std::string targetfn, elfio &reader)
{
	std::string rela_sec_str = ".rela";
	rela_sec_str.append(base_sec->get_name());
	rela_sec_str.append(".");
	rela_sec_str.append(targetfn);
	
	section* sym_sec = reader.sections[ ".symtab" ];
	
	//Create relocation section
	section* rela_sec = reader.sections.add( rela_sec_str );
	rela_sec->set_type( SHT_RELA );
	rela_sec->set_flags( SHF_INFO_LINK );
	rela_sec->set_info( base_sec->get_index() );
	rela_sec->set_addr_align( 0x4 );
	rela_sec->set_entry_size( reader.get_default_entry_size( SHT_RELA ) );
	rela_sec->set_link( sym_sec->get_index() );

	return rela_sec;
}


/* Add new relocation
 *
 * :params
 *   rela_sec Relocation section where to add the new relocation
 *   offset   The offset to patch in the base section
 *   addend   Relocation ADDEND
 *   info     Relocation info (contains symbol number in the symbol table)
 */
int add_reloc(section *rela_sec, Elf64_Addr offset, Elf_Xword info, Elf_Sxword addend, elfio &reader)
{
	relocation_section_accessor rela_acc( reader, rela_sec );
	rela_acc.add_entry( offset, info, addend );
	return 0;
}

/* Loop over all symbols in the symbol table until we find the one with the
 * matching name */
Elf_Xword get_symbol_idx(struct symbol symb, const symbol_section_accessor &symbols) {
	Elf_Xword j = 0;
	struct symbol tmp;
	for (j = 0; j < symbols.get_symbols_num(); ++j ) {
		symbols.get_symbol(j, tmp.name, tmp.value, tmp.size, tmp.bind, tmp.type, tmp.section_index, tmp.other);
		if(symb.value == tmp.value)
		{
			return j;
		}
	}
	return 0;
}

/* Make the symbol UND. We overwite raw bytes corresponding
 * the symbol to UNDEF in the symbol table */
void undefine_symbol(struct symbol sym, elfio &reader) {
	section* sym_sec = reader.sections[ ".symtab" ];
	const char *section_data = sym_sec->get_data();
	const char *symbol_ptr;

	Elf64_Addr offset = sym.index*SYMBOL_ENTRY_SIZE;
	symbol_ptr = section_data+offset;

	section *strtab_section = reader.sections[ ".strtab" ];
	const string_section_accessor strings(strtab_section);

	Elf64_Sym_xx *entry;
	entry = (Elf64_Sym_xx *)symbol_ptr;

	const char *name = strings.get_string(entry->st_name);
	spdlog::debug("Undefining symbol:{}", name);

	entry->st_info  = 0x10;
	entry->st_other = 0;
	entry->st_shndx = 0;
	entry->st_value = 0;
	entry->st_size  = 0;
	return;
}

/* Restore relocations for BL instructions
 * (currently only within a function <targetfn>)
 * that were lost during static linking. This function uses capstone engine for
 * disassembling  */
void fix_bl_instructions(struct symbol &targetfn_sym, const symbol_section_accessor symbols, elfio &reader)
{
	const char *section_data;
	unsigned int j;
	std::string targetfn_name = targetfn_sym.name;
	section* targetfn_section;
	targetfn_section = reader.sections[targetfn_sym.section_index];
	/* ADRP patching */
	std::__cxx11::list<cs_insn> unpaired_adrps; 
	std::list<cs_insn>::iterator it;
	cs_regs regs_read, regs_write;
	uint8_t read_count, write_count;
	
	/* Create a new reloca section */
	section *new_rela_sec = add_new_rela_sec(targetfn_section, targetfn_name, reader);

	/* Disassemble and find bl instructions */
	section_data = reader.sections[targetfn_sym.section_index]->get_data();
	csh handle;
	cs_insn *insn;
	size_t count; /* The number of successfully disasse isntructions */
	bool ret;
	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) /* Initialize Capstone engine for ARM64 */
	{
		spdlog::error("Could not initilize capstone");
		exit(0);
	}
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON
	/* Disassemble until the function end. Yes, just one line to disassemble. */
	count = cs_disasm(handle, (const uint8_t*)section_data+targetfn_sym.offset, targetfn_sym.size, targetfn_sym.value, 0, &insn);

	if (count == 0) {
		spdlog::error("Failed to disassemble target function, probably a bug. Abort!\n");
		exit(0);
	}
	spdlog::info("Disassembled target function, total instructions: {}. Restoring relocations for BL instructions in this function.", count);

	/* Now let's parse the disassembled instructions */
	struct symbol sym; // This will be the destination symbol of the instruction, for example <printk>
	/* We go instruction by instruction and check if we have a BL, ADRP, ADD, or LDR */
	for (j = 0; j < count; j++) {
		if( (insn[j].id == ARM64_INS_BL) ) {
			/* NOTE: the following doesn't seem to be needed after all
			// Remove adrps from unpaired_adrps that don't use caller/callee saved registers (only x9-x28 are good)
			for (it = unpaired_adrps.begin(); it != unpaired_adrps.end(); ++it) {
				cs_regs_access(handle, &(*it), regs_read, &read_count, regs_write, &write_count);
				uint8_t adrp_insn_reg = regs_write[0];
				if ( (adrp_insn_reg < 227) || (adrp_insn_reg > 246) ) {
					unpaired_adrps.erase(it);
				}
			}*/
			/* We are looking at BL. Its argument is the branch destination address.
			 * Let's find out if this address matches any of the symbols' values in the symbol table */
			Elf64_Addr bl_dest_address= std::strtoull(insn[j].op_str+1, NULL, 0); /*opt_str+1 is because the first argument start with # prefix */
			ret = symbols.get_symbol(bl_dest_address, sym.name, sym.size, sym.bind, sym.type, sym.section_index, sym.other);
			if(ret) /* We found a match! */
			{
				/* <sym> is simply our local copy of the symbol. We did not set some of its
				 * fields, so let's do it now */
				sym.value = bl_dest_address;
				sym.index = get_symbol_idx(sym, symbols);
				assert(sym.index);

				/* We finally are going to add the relocation for the BL instruction.
				*  For this, we need to set 64 bits <info> variable. The left (MSB) half contains
				*  the index of the destination symbol in the symbol table. The right (LSB) contains
				* the type of the relocation, we need AAR64_BL26, which corresponds to 0x11b. */
				Elf_Xword info = sym.index; /* left half */
				info = info << 32;
				Elf_Half reloc_type = 0x0000011b; /* right half */
				info = info | reloc_type;
				/* The new relocation should patch the current instruction
				 * which is at offset INST_SIZE(=4) * INST_NUM(=j)
				 * from the <targetfn> start */
				add_reloc(new_rela_sec, targetfn_sym.offset + 4*j , info, 0, reader);
				spdlog::info("\t\t{:016x}\t {}\t\t{}\t<{}> \033[1;32m[RESTORED]\033[0m", insn[j].address, insn[j].mnemonic, insn[j].op_str, sym.name);
			}
			else
				spdlog::debug("\t{:016x}\t {}\t\t{}\t<UNDEF>", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		} else if ( (insn[j].id == ARM64_INS_ADRP) ) { 
			unpaired_adrps.push_front(insn[j]);
			//printf("%lu\n", unpaired_adrps.size());
			spdlog::debug("\t{:016x}\t {}\t\t{}\t<UNPAIRED>", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		} else if ( (insn[j].id == ARM64_INS_ADD) ) { 
			cs_regs_access(handle, &insn[j], regs_read, &read_count, regs_write, &write_count);
			uint8_t add_insn_reg = regs_read[0];
			bool found_match = false;
			bool found_sym = false;
			for (it = unpaired_adrps.begin(); it != unpaired_adrps.end(); ++it) {
				cs_regs_access(handle, &(*it), regs_read, &read_count, regs_write, &write_count);
				uint8_t adrp_insn_reg = regs_write[0];
				if ( (adrp_insn_reg == add_insn_reg) ) {
					char* adrp_dest_ptr = std::find(it->op_str, insn[j].op_str+160, '#'); /*get pointer to # in op_str, which is the dest */
					char* add_dest_ptr = std::find(insn[j].op_str, insn[j].op_str+160, '#'); /*get pointer to # in op_str, which is the dest */
					Elf64_Addr adrp_dest = std::strtoull(adrp_dest_ptr+1, NULL, 0); /*opt_str+1 is because the first argument start with # prefix */
					Elf64_Addr add_dest = std::strtoull(add_dest_ptr+1, NULL, 0); /*opt_str+1 is because the first argument start with # prefix */
					Elf64_Addr real_dest = adrp_dest + add_dest;
					ret = symbols.get_symbol(real_dest, sym.name, sym.size, sym.bind, sym.type, sym.section_index, sym.other);
					if(ret) /* We found a match! */
					{
						/* See "bl" case above for explanation of each part*/
						sym.value = real_dest;
						sym.index = get_symbol_idx(sym, symbols);
						assert(sym.index);
						
						Elf_Xword info = sym.index; /* left half */
						info = info << 32;
						Elf_Half reloc_type = 0x00000113; /* right half */
						Elf_Xword adrp_reloc_info = info | reloc_type;
						reloc_type = 0x00000115; /* right half */
						Elf_Xword add_reloc_info = info | reloc_type;
						
						add_reloc(new_rela_sec, targetfn_sym.offset + it->address - insn[0].address , adrp_reloc_info, 0, reader);
						add_reloc(new_rela_sec, targetfn_sym.offset + 4*j , add_reloc_info, 0, reader);
						spdlog::info("\t\t{:016x}\t {}\t\t{}\t<{}> \033[1;32m[RESTORED]\033[0m", insn[j].address, insn[j].mnemonic, insn[j].op_str, sym.name);
						found_sym = true;
					}
					found_match = true;
					unpaired_adrps.erase(it); /* we've matched the adrp, so remove it from the list */
					break;
				}
			} 
			if (!found_match) {
				spdlog::debug("\t{:016x}\t {}\t\t{}\t<UNPAIRED>", insn[j].address, insn[j].mnemonic, insn[j].op_str);
			} else if (!found_sym) {
				spdlog::debug("\t{:016x}\t {}\t\t{}\t<NO SYM>", insn[j].address, insn[j].mnemonic, insn[j].op_str);
			}
		} else if ( (insn[j].id == ARM64_INS_LDR) ) {
			cs_arm64_op *op = &(insn[j].detail->arm64.operands[1]); //cs_regs_access won't recover the "read" registers for LDRs
			uint8_t ldr_insn_reg = op->mem.base;
			Elf64_Addr ldr_dest = op->mem.disp;
			bool found_match = false;
			bool found_sym = false;
			for (it = unpaired_adrps.begin(); it != unpaired_adrps.end(); ++it) {
				cs_regs_access(handle, &(*it), regs_read, &read_count, regs_write, &write_count);
				uint8_t adrp_insn_reg = regs_write[0];
				if ( (adrp_insn_reg == ldr_insn_reg) ) {
					char* adrp_dest_ptr = std::find(it->op_str, insn[j].op_str+160, '#'); /*get pointer to # in op_str, which is the dest */
					char* ldr_dest_ptr = std::find(insn[j].op_str, insn[j].op_str+160, '#'); /*get pointer to # in op_str, which is the dest */
					Elf64_Addr adrp_dest = std::strtoull(adrp_dest_ptr+1, NULL, 0); /*opt_str+1 is because the first argument start with # prefix */
					Elf64_Addr real_dest = adrp_dest + (Elf64_Addr)ldr_dest;
					ret = symbols.get_symbol(real_dest, sym.name, sym.size, sym.bind, sym.type, sym.section_index, sym.other);
					if(ret) /* We found a match! */
					{
						/* See "bl" case above for explanation of each part*/
						sym.value = real_dest;
						sym.index = get_symbol_idx(sym, symbols);
						assert(sym.index);
						
						Elf_Xword info = sym.index; /* left half */
						info = info << 32;
						Elf_Half reloc_type = 0x00000113; /* right half */
						Elf_Xword adrp_reloc_info = info | reloc_type;
						reloc_type = 0x0000011e; /* right half */
						Elf_Xword ldr_reloc_info = info | reloc_type;
						
						add_reloc(new_rela_sec, targetfn_sym.offset + it->address - insn[0].address , adrp_reloc_info, 0, reader);
						add_reloc(new_rela_sec, targetfn_sym.offset + 4*j , ldr_reloc_info, 0, reader);
						spdlog::info("\t\t{:016x}\t {}\t\t{}\t<{}> \033[1;32m[RESTORED]\033[0m", insn[j].address, insn[j].mnemonic, insn[j].op_str, sym.name);
						
						found_sym = true;
					}
					found_match = true;
					unpaired_adrps.erase(it); /* we've matched the adrp, so remove it from the list */
					break;
				}
			} 
			if (!found_match) {
				spdlog::debug("\t{:016x}\t {}\t\t{}\t<UNPAIRED>", insn[j].address, insn[j].mnemonic, insn[j].op_str);
			} else if (!found_sym) {
				spdlog::debug("\t{:016x}\t {}\t\t{}\t<NO SYM>", insn[j].address, insn[j].mnemonic, insn[j].op_str);
			}
		} else {
			spdlog::debug("\t{:016x}\t {}\t\t{}", insn[j].address, insn[j].mnemonic, insn[j].op_str);
		}
	}
	cs_free(insn, count);
	cs_close(&handle);
	return;
}


int main( int argc, char** argv )
{
	elfio reader;

	unsigned int i,j;

	/* Ucomment to set the debug level */
	spdlog::set_level(spdlog::level::debug); // Set global log level to debug

	/* Parse command line args */
	if ( argc != 3 ) {
		std::cout << "Create relocation entries for statically" << std::endl;
		std::cout << "linked BL instructions (within specified function)," << std::endl;
		std::cout << "and change file type to relocatable." << std::endl;
 		std::cout << "Usage: relocator <vmlinux_file> <function_name>" << std::endl;
 		std::cout << "    example: relocator vmlinux meson_uvm_init" << std::endl;
		std::cout << "    The result will be written to tmp.elf. The original file will remain unchanged." << std::endl;
 		exit(0);
	}
	spdlog::set_pattern("[%^%l%$] %v");

	if ( !reader.load( argv[1] ) ) {
		spdlog::error("Can't parse the input ELF file, exiting");
	 	exit(0);
	}
	spdlog::info("Input file `{}` loaded successfully to memory. Working with in-memory copy.", argv[1]);

	Elf_Xword targetfn_index = atoi(argv[2]);


	/* Search for symbol table, exit if not found */
	Elf_Half sec_num = reader.sections.size();
	section* symbols_section = NULL;
	for (i = 0; i < sec_num; ++i ) {
	 	symbols_section = reader.sections[i];
		if ( symbols_section->get_type() == SHT_SYMTAB ) {
			spdlog::info("Symbol table found: [{}]", symbols_section->get_name());
			break;
		}
	}
	if(!symbols_section) {
		spdlog::error("Could not find symbol table, exiting");
	 	exit(0);
	}

	/* <targetfn> is the function who's BL instrutions we want
	 * to make relocatable again. Currently they ar statically linked and point to Android's version of the functions.
	 *
	 * Our first step is to locate this funtion in the binary, let's parse the symbol table to find its address.
	 * Lots of long lines below ALAS, but the only important thing is the call to symbols.get_symbol() */
	struct symbol targetfn_sym;
	targetfn_sym.index = targetfn_index;
	section* targetfn_section;
	const symbol_section_accessor symbols(reader, symbols_section);
	if(symbols.get_symbol(targetfn_sym.index, targetfn_sym.name, targetfn_sym.value, targetfn_sym.size, targetfn_sym.bind, targetfn_sym.type, targetfn_sym.section_index, targetfn_sym.other)) {
		targetfn_section = reader.sections[targetfn_sym.section_index];
		targetfn_sym.offset = targetfn_sym.value - targetfn_section->get_address();
		spdlog::info("Target function found:");
		spdlog::info("  [{}] in section #{} [{}] at offset [{}] from section start",
			targetfn_sym.name, targetfn_sym.section_index, 
			reader.sections[targetfn_sym.section_index]->get_name(),
			fmt::format("0x{:06x}", targetfn_sym.offset));
	}
 	else {
		spdlog::error("Could not find target function, exiting");
	 	exit(0);
	}

	/* Make BL instructions relocatable within targetfn */
	fix_bl_instructions(targetfn_sym, symbols, reader);

	spdlog::info("Saving the result to the input file location");
	reader.save( argv[1] );
}


