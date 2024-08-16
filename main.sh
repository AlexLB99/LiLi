#!/bin/bash

#/* STEPS:
# * 	1. Extract the ELF sections from vmlinux, and combine them into one binary blob
# *	2. Compile a tiny module, and insert this binary blob into the module's .text section
# *	3. Put all the symbol table entries relevant to our module in a list (symSet)
# *	4. Add these symbols (in symSet) to our module
# *	5. For each of these symbols, call [relocator vmlinux symbol]
# *	6. Copy the relocations we added in step 5 (via relocator) to our module
# *		If the relocation uses a symbol absent from our module, add that symbol to the module
# *		If the relocation uses a symbol present in our module but is UND, don't add the relocation
# *	7. Patch .rela.gnu.linkonce.this_section to have the correct entry point for our module
#*/

if [ $# -lt 2 ]
  then
    echo "First argument should be path to ELF file (e.g., vmlinux)"
    echo "All subsequent arguments should be names of source files for the driver"
    echo "Ex: main.sh test/vmlinux file1.c file2.c"
    echo "NOTE: these source files should be in the src_tags/ folder"
    exit
fi
input_file=$1
shift; #we don't need that arg anymore
driver_name=$1 #we just use this to name our module later on

#Preliminary steps
# * NOTE: we strip all symbols named $x from vmlinux -- these are debugging symbols that are at the 
# * same offset as FUNC symbols (which could interfere with fix_bl_instructions() in relocator)
input_file_stripped="$input_file.stripped"
aarch64-linux-gnu-objcopy -w --strip-symbol="\$x" --strip-symbol="\$d" --strip-symbol="__key.*" $input_file $input_file_stripped #strip debugging symbols since they cause issues
rm -rf tmp_bin
mkdir tmp_bin

#/* We extract all ELF sections from vmlinux between .head.text and .mmuoff.data.read, and combine
# * them into a single ELF file.
#*/
echo "[+] Combining ELF sections"
vmlinux_section_table=$(readelf -S $input_file_stripped --wide)
vmlinux_section_table=$(echo "$vmlinux_section_table" | sed 1,5d | awk '/.head.text/,/.bss/' | head -n -1) #get all sections before .bss
first_sec_addr=$(echo "$vmlinux_section_table" | head -n 1 | awk -F] '{print $2}' | awk '{print $3}')
first_sec_addr_dec=$(echo "ibase=16; ${first_sec_addr^^}" | bc)

while IFS= read -r readelf_S_line; do
	#get section's name and offset:
	sec_name=$(echo $readelf_S_line | awk -F] '{print $2}' | awk '{print $1}')
	sec_addr=$(echo $readelf_S_line | awk -F] '{print $2}' | awk '{print $3}')
	
	#dump the section into a binary file
	bin_dump_name="tmp_bin/$sec_name.bin"
	aarch64-linux-gnu-objcopy --dump-section $sec_name=$bin_dump_name $input_file_stripped
	
	#concatenate the bin file to our main bin blob (at the right offset)
	sec_addr_dec=$(echo "ibase=16; ${sec_addr^^}" | bc)
	real_sec_offset="$(bc <<< "$sec_addr_dec - $first_sec_addr_dec")"
	truncate -s $real_sec_offset tmp_bin/all_sections.bin #pad to the right size
	dd if=$bin_dump_name of=tmp_bin/all_sections.bin status=none conv=notrunc oflag=append
	
	echo "concatenated $sec_name"
done <<< "$vmlinux_section_table"

#finally, add the .bss section
bss_sec_entry=$(readelf -S $input_file_stripped --wide | grep -w "\.bss")
sec_addr=$(echo $bss_sec_entry | awk -F] '{print $2}' | awk '{print $3}')
sec_addr_dec=$(echo "ibase=16; ${sec_addr^^}" | bc)
real_sec_offset="$(bc <<< "$sec_addr_dec - $first_sec_addr_dec")"
sec_size=$(echo $bss_sec_entry | awk -F] '{print $2}' | awk '{print $5}')
sec_size_dec=$(echo $((16#$sec_size)))
bss_end_offset="$((real_sec_offset+sec_size_dec))"
truncate -s $bss_end_offset tmp_bin/all_sections.bin #pad to end of .bss


#/* Compile an empty module, then insert our extracted binary into this module (in the .text section). 
# * We also make the .text section writable, since it'll contain data
#*/
echo "[+] Adding combined section to new .ko"
cp inject_base.c inject2.c
drv_name=${driver_name::-2}
sed -i '1i#define NAME "'"$drv_name"'"' inject2.c #ensures each module uses unique name in case we need to insert multiple
make inject
aarch64-linux-gnu-objcopy --update-section .text=tmp_bin/all_sections.bin inject2.o blob-injected.ko
aarch64-linux-gnu-objcopy --set-section-flags .text=code,alloc blob-injected.ko
rm inject2.c inject2.o


#/* Find all the symbol table entries in vmlinux that correspond to declarations in our driver's
# * source files. LOCAL symbols for a module are grouped together right after a symbol with type 
# * FILE with the name of the source file (e.g., dolby_fw.c). GLOBAL symbols are placed haphazardly
# * in the symtab, so we identify their names by scanning the source files with ctags.
#*/
echo "[+] Collecting driver's symbols"
vmlinux_symtab="$(readelf -s $input_file_stripped --wide | sed 1,3d)"
symSet=""
for src_file in "$@"
do
	if [ ! -f "src_tags/$src_file" ]; then
	    echo "ERROR: src_tags/$src_file does not exist!"
	    echo "Copy over the relevant .c file to src_tags/"
	    exit
	fi
	
	#	Step 1: iterate over the module's symtab entries for local symbols and build S from it
	symSetTemp=""
	if [[ ! -z $symSet ]]; then #if we already have stuff in S, add a newline before we start adding things again
		symSetTemp+="\n"
	fi
	src_file_sym="$(readelf -s $input_file_stripped --wide | awk -v file_name="$src_file" '{if ($8 == file_name) print $0}')"
	symtab_sec=$(readelf -s $input_file_stripped --wide | grep "$src_file_sym" -A 10000 | awk -vN=2 'n<2;/FILE/{++n}' | sed 1,1d | sed '$d') #the part of the vmlinux symbol relevant to the module
	if [[ -n $symtab_sec ]]; then #sometimes after removing debugging symbols, some files have no local syms
		while IFS= read -r line; do
			symSize=$(echo $line | awk '{print $3}')
			symName=$(echo $line | awk '{print $8}')
			
			symSetTemp+="$line\n"
			#if [[ $symSize > 0 ]]; then
			#	symSetTemp+="$line\n"
			#fi
		done <<< "$symtab_sec"
	fi
	

	#	Step 2: add non-local (GLOBAL and WEAK) symbols to S
	globFuncTags=$(ctags -x --c-types=f --file-scope=no src_tags/$src_file)
	globVarTags=$(ctags -x --c-types=v --file-scope=no src_tags/$src_file)
	srcFuncs=$(echo "$globFuncTags" | awk '{print $1}') #get global func names from source file
	srcVars=$(echo "$globVarTags" | awk '!/EXPORT_SYMBOL/' | awk '{print $1}') #get global var names from source file (remove export_symbol lines to avoid duplicates)
	srcSyms=$(echo -e "$srcFuncs\n$srcVars" | awk 'NF')
	while IFS= read -r line; do #if the sym name corresponds to a non-local symbol in vmlinux_symtab, then we add it to S
		sym_is_weak=$(echo "$globFuncTags" | grep -w "__weak" | grep -w $line)
		if [[ -n $sym_is_weak ]]; then #searches for either weak or global symbol
			nonLocSym=$(echo "$vmlinux_symtab" | grep -w $line | awk -v sym_bind="WEAK" '{if ($5 == sym_bind) print $0}') #non-empty if the symbol name ($line) corresponds to a weak symbol in vmlinux
		else
			nonLocSym=$(echo "$vmlinux_symtab" | grep -w $line | awk -v sym_bind="GLOBAL" '{if ($5 == sym_bind) print $0}') #non-empty if the symbol name ($line) corresponds to a global symbol in vmlinux
		fi
		
		if [[ -n $nonLocSym ]]; then
			symSetTemp+="$nonLocSym\n"
		fi
	done <<< "$srcSyms"
	symSet+="$(echo -e "$symSetTemp")" #escape the newlines
done


#/* Add the symbols that correspond to declarations made by our driver (which we stored in symSet)
# * to our module. We need to add them because the "relocator" program will look for functions by
# * parsing the symbol table. Moreover, another reason we need GLOBAL symbols in particular is that
# * the kernel will need them in order to make the corresponding funcs/objects available to the rest
# * of the kernel.
# * new_sym_offset = old_sym_offset - first_sec_address
# * 	old_sym_offset is the sym's offset (address in this case) in vmlinux
# *	first_sec_address is the address of the first section (.head.text)
# * 	new_sym_offset is the sym's offset in our module's .text section
#*/
echo "[+] Adding driver's symbols to module"
first_sec_address=$(echo "$vmlinux_section_table" | head -n 1 | awk -F] '{print $2}' | awk '{print $3}')
first_sec_address_dec=$(echo "ibase=16; ${first_sec_address^^}" | bc)
while IFS= read -r symtab_entry; do
	old_sym_offset=$(echo $symtab_entry | awk '{print $2}')
	old_sym_offset_dec=$(echo "ibase=16; ${old_sym_offset^^}" | bc)
	sym_size=$(echo $symtab_entry | awk '{print $3}')
	sym_type=$(echo $symtab_entry | awk '{print $4}')
	sym_bind=$(echo $symtab_entry | awk '{print $5}')
	sym_vis=$(echo $symtab_entry | awk '{print $6}')
	sym_name=$(echo $symtab_entry | awk '{print $8}')
	echo $symtab_entry
	
	new_sym_offset=$(bc <<< "$old_sym_offset_dec - $first_sec_address_dec")
	
	./new_symbol blob-injected.ko $sym_name $new_sym_offset $sym_size $sym_bind $sym_type $sym_vis ".text" blob-injected.ko
done <<< "$symSet"


#/* Call "relocator" program for each FUNC symbol in vmlinux
# * We'll later copy over these relocations from vmlinux to blob-injected
#*/
echo "[+] Adding relocations to vmlinux"
while IFS= read -r symtab_entry; do
	sym_ndx=$(echo $symtab_entry | awk '{print $1}')
	sym_ndx=${sym_ndx::-1} #remove the colon at the end
	sym_type=$(echo $symtab_entry | awk '{print $4}')
	sym_name=$(echo $symtab_entry | awk '{print $8}')
	
	if [[ $sym_type == "FUNC" ]]; then
		echo "Adding relocations in $sym_name"
		./relocator $input_file_stripped $sym_ndx
	fi
done <<< "$symSet"


#/* Now, we can copy over the relocations that we added in vmlinux to our module. We iterate over the
# * relocation table (readelf -r) line by line. When the line introduces a new rela section
# * (e.g., "Relocation section '.rela.text' at offset 0x177dc64 contains 84 entries"), we store the
# * index of the section modified by that rela section for later use. When the line contains a relocation
# * entry, we add the corresponding symbol (undefined) to our module (if it isn't already there), and we
# * then add the relocation entry at the correct offset in .text if the symbol it uses is undefined in blob-injected.
# * If it isn't undefined, then it's a symbol declared by our module, so we don't need a relocation (it'll just use the
# * bl statement's relative address).
# * NOTE: we remove the ".rela" section from our copy of the relocation table at the beginning, so we only parse
# * relocation sections that we added (".rela" was the only relocation section in vmlinux before)
#*/
echo "[+] Copying relocations from vmlinux to module"
vmlinux_reloc_table=$(readelf -r $input_file_stripped --wide | awk -v 'n=2' '/Relocation section/ && !--n, 0') #we remove the .rela entries since we won't need them
./new_rela_sec blob-injected.ko ".text" blob-injected.ko #we'll put all the relocations in .rela.text
#go line by line (and thus rela section by rela section) and parse the entries
modified_sec_ndx=""
while IFS= read -r reloc_table_line; do
	is_new_rela_sec=$(echo $reloc_table_line | grep "Relocation section") #line introduces new rela section
	is_rela_line=$(echo $reloc_table_line | grep "R_AARCH64_CALL26\|R_AARCH64_ADR_PREL_PG_HI21\|R_AARCH64_ADD_ABS_LO12_NC\|R_AARCH64_LDST64_ABS_LO12_NC") #line is for rela entry (we only added CALL26 relocations)
	
	if [[ ! -z $is_new_rela_sec ]]; then #if the line introduces a new rela section, update the sec index that we work with
		curr_rela_sec=$(echo $reloc_table_line | sed -n "s/^.*'\(.*\)'.*$/\1/ p") #get the name of the rela section, which is between single quotes
		modified_sec_ndx=$(readelf -S $input_file_stripped --wide | awk -F] '{print $2}' | awk -v rela_sec="$curr_rela_sec" '{if ($1 == rela_sec) print $9;}') #index of the section modified by the rela section
	elif [[ ! -z $is_rela_line ]] ; then #if the line is a relocation entry, add that relocation entry to the blob
		#1. if we don't already have the symbol in the module, add it. If we have it & it's not UND, then continue to next line (no reloc is needed)
		sym_name=$(echo $reloc_table_line | awk '{print $5}')
		
		is_sym_in_target_kernel=$(grep -w $sym_name src_tags/System.map) #if sym is OBJECT and isn't in target kernel, we'll just use the vmlinux object
		if [[ -z $is_sym_in_target_kernel && -n $(echo $reloc_table_line | grep "OBJECT") ]]; then
			echo "[-] WARNING: $sym_name not declared by module and absent from System.map!"
			continue
		fi
		
		is_sym_in_mod=$(readelf -s blob-injected.ko --wide | grep -w $sym_name)
		if [[ -z $is_sym_in_mod ]]; then #if sym isn't in mod, add it
			./new_symbol blob-injected.ko $sym_name 0 0 "GLOBAL" "NOTYPE" "DEFAULT" "" blob-injected.ko
		else
			is_sym_und=$(readelf -s blob-injected.ko --wide | grep -w $sym_name | grep "UND")
			if [[ -z $is_sym_und ]]; then #if the symbol is in our module and isn't UND, then the symbol is declared by our module, so we don't need a reloc
				continue
			fi
		fi
		
		if [[ $sym_name == "__stack_chk_guard" ]]; then #adding relocations to __stack_chk_guard causes problems
			continue
		fi
		
		#2. add the relocation to the module
		#OFFSET computation for relocation
		old_rel_offset=$(echo $reloc_table_line | awk '{print $1}')
		old_rel_offset_dec=$(echo "ibase=16; ${old_rel_offset^^}" | bc)
		vmlinux_sec_info=$(readelf -S $input_file_stripped --wide | grep -w "$modified_sec_ndx]")
		vmlinux_sec_addr=$(echo $vmlinux_sec_info | awk -F] '{print $2}' | awk '{print $3}')
		vmlinux_sec_addr_dec=$(echo "ibase=16; ${vmlinux_sec_addr^^}" | bc)
		new_rel_offset=$(bc <<< "$vmlinux_sec_addr_dec - $first_sec_address_dec + $old_rel_offset_dec")
		#INFO computation for relocation
		mod_nonlocal_syms=$(readelf -s blob-injected.ko --wide | grep -w "GLOBAL\|WEAK")
		mod_sym_ndx=$(echo "$mod_nonlocal_syms" | awk -v sym_name="$sym_name" '{if ($8 == sym_name) print substr($1, 1, length($1)-1);}') 
		mod_sym_ndx_hex=$(printf '%x\n' $mod_sym_ndx)
		old_rel_info=$(echo $reloc_table_line | awk '{print $2}')
		rel_type=${old_rel_info: -8}
		rel_info_hex="$mod_sym_ndx_hex$rel_type"
		rel_info_dec=$(echo $((16#$rel_info_hex)))
		#	2.3 add the relocation
		./new_reloc blob-injected.ko $new_rel_offset $rel_info_dec 0 ".rela.text" blob-injected.ko
	fi
done <<< "$vmlinux_reloc_table"


#/* Now we copy over some relocations that were already in vmlinux. In particular, for each of our module's
# * symbols, we intend to copy over all relocations in the ranges covered by those symbols. We need to calculate
# * the offset, the info, and the addend. Of note, we replace R_AARCH64_RELATIVE with R_AARCH64_ABS64, since the
# * former is not supported by the kernel module loader. 
# * We put this functionality in a function so that we can call it recursively. The logic works as follows:
# * ------------------------------
# * symbol_extract(symbol s):
# * 	get list of relocations (R) involved in the memory region designated by symbol s
# * 	for each r in R:
# * 		if r points to crc symbol then
# * 			add relocation r (special case)
# * 			continue
# * 		if r points to UND symbol then
# * 			add relocation r (special case)
# * 			continue
# * 		add relocation r
# * 		if r points to symbol z && z isn't in our module
# * 			copy over symbol z to module
# * 			symbol_extract(z)
# *  ------------------------------
# * We need this recursiveness because an object declared by the module could have pointers to other objects, which
# * might also use relocations (so we need to add these relocations as well, or else we might get a null ptr deref).
# * This second object might also point to other objects as well, so on and so forth...
#*/
echo "[+] Copying old relocations from vmlinux to module"
symbol_extract () { #takes as input the "readelf -s" output for a symbol in vmlinux
	echo "Looking for relocs in following symbol:"
	echo $@

	sym_addr=$2
	sym_addr_dec=$(echo "ibase=16; ${sym_addr^^}" | bc) #use bc for large number conversion
	sym_size=$3
	sym_end=$(bc <<< "$sym_addr_dec + $sym_size - 4") #use bc since we are using large numbers
	
	first_match_done=0
	curr_vml_reloc_table=$(readelf -r $input_file_stripped --wide) #refresh the relocation table string since this loop modifies it
	for i in `seq $sym_addr_dec 4 $sym_end`; do  #iterate over addresses in symbol's range to find relocations
		vml_ofs=$(echo "obase=16; $i" | bc) #vmlinux offset (current address in for loop)
		vml_ofs=${vml_ofs,,} #make the offset lowercase to match readelf's case
		reloc_line=$(echo "$curr_vml_reloc_table" | awk -v sym_ofs="$vml_ofs" '{if ($1 ~ sym_ofs) print $0}')
		
		if [[ $reloc_line ]]; then #we've found a relocation that matches the current address
			if [ $first_match_done -eq 0 ]; then #First time we find a match, shorten the reloc table for performance
				curr_vml_reloc_table=$(echo "$curr_vml_reloc_table" | grep "$reloc_line" -A $(($sym_size/4)))
				first_match_done=1
			fi
			echo "Copying relocation:"
			echo $reloc_line
			
			rel_offset=$(echo $reloc_line | awk '{print $1}')
			rel_offset_dec=$(echo "ibase=16; ${rel_offset^^}" | bc)
			rel_addend=$(echo $reloc_line | awk '{print $4}')
			
			#if addend is positive, it's a crc symbol, and needs to be treated separately (the sym val is a checksum, not an offset)
			if [[ -z $(echo $rel_addend | grep "-") ]]; then
				padded_sym_val=$(printf "%016X\n" "0x$rel_addend")
				padded_sym_val_lc=${padded_sym_val,,}
				crc_sym=$(readelf -s $input_file_stripped --wide | awk -v sym_val="$padded_sym_val_lc" '{if ($2 == sym_val) print $0}')
				crc_sym_name=$(echo $crc_sym | awk '{print $8}')
				rel_addend=$(echo "$rel_addend")
				sym_val_dec=$(echo "ibase=16; ${rel_addend^^}" | bc)
				./new_symbol blob-injected.ko $crc_sym_name $sym_val_dec 0 "GLOBAL" "NOTYPE" "DEFAULT" "ABS" blob-injected.ko
				
				#OFFSET computation
				new_offset_dec=$(bc <<< "$rel_offset_dec - $first_sec_address_dec")
				#INFO computation
				blob_crc_sym=$(readelf -s blob-injected.ko --wide | grep "$crc_sym_name")
				blob_crc_sym_ndx=$(echo $blob_crc_sym | awk '{print $1}')
				blob_crc_sym_ndx=${blob_crc_sym_ndx::-1} #remove the colon at the end
				blob_crc_sym_ndx_hex=$(printf '%x\n' $blob_crc_sym_ndx)
				new_info=$blob_crc_sym_ndx_hex"00000101"
				new_info_dec=$(echo "ibase=16; ${new_info^^}" | bc)
				
				./new_reloc blob-injected.ko $new_offset_dec $new_info_dec 0 .rela.text blob-injected.ko
				continue
			fi
			#it's not a crc symbol, so we'll just relocate relative to the beginning of the module .text section
			
			rel_addend_neg=${rel_addend:1} #remove the negative sign
			rel_addend_neg_dec=$(echo "ibase=16; ${rel_addend_neg^^}" | bc)
			rel_addend_dec=$(bc <<< "18446744073709551616 - $rel_addend_neg_dec") #2^64 + negative addend
			rel_addend_hex=$(printf '%x\n' $rel_addend_dec)
			
			rel_uses_ext_func=$(echo "$vmlinux_symtab" | awk -v offset="$rel_addend_hex" '{if ($2 == offset && ($5 == "GLOBAL" || $5 == "WEAK")) print $0}')
			if [[ -n $rel_uses_ext_func ]]; then
				sym_name=$(echo $rel_uses_ext_func | awk '{print $8}')
				is_sym_in_target_kernel=$(grep -w $sym_name src_tags/System.map)
				if [[ -n $is_sym_in_target_kernel || -z $(echo $rel_uses_ext_func | grep "OBJECT") ]]; then #add reloc to UND sym unless it's an object that isn't in target kernel
					is_sym_in_mod=$(readelf -s blob-injected.ko --wide | grep -w $sym_name | grep "GLOBAL\|WEAK")
					if [[ -z $is_sym_in_mod ]]; then #if sym isn't in mod, add it
						./new_symbol blob-injected.ko $sym_name 0 0 "GLOBAL" "NOTYPE" "DEFAULT" "" blob-injected.ko
					fi
					
					is_sym_und=$(readelf -s blob-injected.ko --wide | grep -w $sym_name | grep -w "UND")
					if [[ -n $is_sym_und ]]; then #if symbol is UND, add relocation to that symbol
						#OFFSET computation
						new_offset_dec=$(bc <<< "$rel_offset_dec - $first_sec_address_dec")
						#INFO computation
						blob_und_sym_ndx=$(echo $is_sym_und | awk '{print $1}')
						blob_und_sym_ndx=${blob_und_sym_ndx::-1} #remove the colon at the end
						blob_und_sym_ndx_hex=$(printf '%x\n' $blob_und_sym_ndx)
						new_info=$blob_und_sym_ndx_hex"00000101"
						new_info_dec=$(echo "ibase=16; ${new_info^^}" | bc)
						./new_reloc blob-injected.ko $new_offset_dec $new_info_dec 0 .rela.text blob-injected.ko
						continue
					fi
				else
					is_sym_in_mod=$(readelf -s blob-injected.ko --wide | grep -w $sym_name | grep "GLOBAL\|WEAK")
					if [[ -z $is_sym_in_mod ]]; then #if sym isn't in mod, add it
						echo "[-] WARNING: $sym_name not declared by module and absent from System.map!"
					fi
				fi
			fi
			
			#OFFSET computation
			new_offset_dec=$(bc <<< "$rel_offset_dec - $first_sec_address_dec")
			#INFO computation
			text_sec_ndx=$(readelf -S blob-injected.ko --wide | awk -F[ '{print $2}' | awk -v sec_name=".text" '{if ($2 == sec_name) print substr($1, 1, length($1)-1)}')
			text_sym_num=$(readelf -s blob-injected.ko --wide | awk -v Ndx="$text_sec_ndx" '{if ($7 == Ndx && $4 == "SECTION") print substr($1, 1, length($1)-1);}')
			text_sec_ndx_hex=$(printf '%x\n' $text_sym_num)
			new_info=$text_sec_ndx_hex"00000101"
			new_info_dec=$(echo "ibase=16; ${new_info^^}" | bc)
			#ADDEND computation
			new_addend_dec=$(bc <<< "$rel_addend_dec - $first_sec_address_dec")
			
			./new_reloc blob-injected.ko $new_offset_dec $new_info_dec $new_addend_dec .rela.text blob-injected.ko
			
			rel_uses_symbol=$(echo "$vmlinux_symtab" | awk -v offset="$rel_addend_hex" '{if ($2 == offset) print $0}')
			if [[ -n $rel_uses_symbol ]]; then
				#check if the symbol is already in the blob
				#echo "RELOCATION POINTS TO SYM"
				new_addend_hex=$(printf '%x\n' $new_addend_dec)
				new_addend_hex=$(printf "%016X\n" "0x$new_addend_hex")
				new_addend_hex=${new_addend_hex,,}
				is_sym_in_mod=$(readelf -s blob-injected.ko --wide | grep "$new_addend_hex")
				if [[ -z $is_sym_in_mod ]]; then #if symbol isn't in mod, add it and call symbol_extract
					echo "NEED TO ADD SYMBOL"
					#add symbol
					rel_sym_size=$(echo $rel_uses_symbol | awk '{print $3}')
					rel_sym_type=$(echo $rel_uses_symbol | awk '{print $4}')
					rel_sym_bind=$(echo $rel_uses_symbol | awk '{print $5}')
					rel_sym_vis=$(echo $rel_uses_symbol | awk '{print $6}')
					rel_sym_name=$(echo $rel_uses_symbol | awk '{print $8}')
					./new_symbol blob-injected.ko $rel_sym_name $new_addend_dec $rel_sym_size $rel_sym_bind $rel_sym_type $rel_sym_vis ".text" blob-injected.ko
					( symbol_extract $rel_uses_symbol ) #rel_uses_symbol is the symtab entry for the reloc's sym in vmlinux
					echo "DONE WITH $rel_sym_name"
				fi
			fi
		fi
	done
}

while IFS= read -r line; do #iterate over the module's symtab entries in vmlinux
	is_sym_func=$(echo $line | grep "FUNC")
	if [[ -z $is_sym_func ]]; then
		symbol_extract $line
	fi
done <<< "$symSet"


#/* We need to put the entry and exit points for our module in .rela.gnu.linkonce.this_module
# * For this, we manually call patch_linkonce.sh with the same arguments as this scripts was
# * called with.
#*/
echo "[+] Creating .rela.gnu.linkonce.this_module"
./new_rela_sec blob-injected.ko .gnu.linkonce.this_module blob-injected.ko

echo "[+] Done, now patch .rela.gnu.linkonce.this_module"
echo "Do: ./patch_linkonce.sh $input_file_stripped $@"



#rm -rf tmp_bin
