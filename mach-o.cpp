/*
*    Open Patcher - A penetration testing and reverse engineering tool for applications
*    Copyright (C) 2013  Dennis Shtatnov <densht@gmail.com>
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "mach-o.h"

//Use this to open a raw file
//This will do magic checking so that FAT/MACH can be handled
IFILE* ifopen(char* file){
	IFILE* f = (IFILE *) malloc(sizeof(IFILE));
	f->magic = 0;

	f->file = fopen(file, "r+b");
	fseek(f->file, 0, SEEK_SET);
	fread(&f->magic, sizeof(uint32_t), 1, f->file);

	return f;
}
void ifclose(IFILE* file){
	fclose(file->file);
	free(file);
}

size_t read_uleb128(char* buf, int* value){
	int shift = 0;
	int res = 0;

	char *byte = buf;
	while(true){ 
		res |= (*byte & B8(01111111) /*0x7f*/) << shift; //01111111

		if((*byte & B8(10000000) /*0x80*/) == 0) //10000000
			break;

		byte++;
		shift += 7;
	}

	*value = res;
	return byte - buf + 1;
}

mach_o::mach_o(IFILE* f){
	memset(this, 0, sizeof(mach_o));


	this->file = f->file;

	//fseek(file, 0, SEEK_SET);
	
	//uint32_t magic;
	//fread(&magic, sizeof(uint32_t), 1, file);


	/* Assumming this has already been checked by the */
	/*if(magic == MH_MAGIC){
		
	}
	else if(magic == FAT_MAGIC){
		printf("Sorry. FAT binaries are currently not supported. Please thin it using lipo.");
		return;
	}
	*/

	fseek(this->file, 0, SEEK_SET);

	fread(&header, sizeof(mach_header), 1, file);


	if(header.flags & MH_PIE != 0){
		//printf("ASLR is enabled.\n");
	}

	commands = (char *) malloc(header.sizeofcmds);
	fread(commands, header.sizeofcmds, 1, file);

	char* p = commands;
	for(int x = 0; x < header.ncmds; x++){
		load_command* cmd = (load_command*) p;
		
		//printf("\n\n");
		switch (cmd->cmd)
		{
		case LC_SEGMENT:
			{
				//CHECK FLAGS FOR CODE SECTIONS VS DATA SECTIONS
				//printf("Segments Command\n-------------------------------\n");
				
				this->nsegments++;
				this->segments = (segment**) realloc(this->segments, sizeof(segment*) * this->nsegments);
				this->segments[this->nsegments - 1] = (segment *) p;
				
				//segment* s = (segment *) p;
				//printf("%X: %s (%X-%x)\n",s->vmaddr, &s->segname, s->fileoff, s->fileoff + s->filesize);
			
				//section* sections = (section *)(p + sizeof(segment_command));

				/*
				for(int y = 0; y < s->nsects; y++){
					printf("    %X:%s (%X-%X)", s->sections[y].addr, s->sections[y].sectname, s->sections[y].offset, s->sections[y].offset + s->sections[y].size );


					int a = s->sections[y].flags & S_ATTR_PURE_INSTRUCTIONS;
					if((s->sections[y].flags & S_ATTR_PURE_INSTRUCTIONS) != 0 || (s->sections[y].flags & S_ATTR_SOME_INSTRUCTIONS) != 0){
						printf(" (CODE)");
					}
					printf("\n");
				};
				*/

			}
			//printf("\n");
			break;

		case LC_ENCRYPTION_INFO:
			{
				//printf("Encryption Info\n-------------------------------\n");
				encryption_info = (encryption_info_command *) p;
				/*if(encryption_info->cryptid == 1){
					printf("BINARY IS ENCRYPTED: Please decrypt first.\n");
				}
				else{
					printf("Binary is decrypted :)\n");
				}*/
			}
			break;
		case LC_SYMTAB:
			{
				//printf("Symbols\n-------------------------------\n");

				symtab_command * syms = (symtab_command *) p;

				symbols.cmd = syms;

				symbols.list = (struct nlist *) malloc(sizeof(struct nlist) * syms->nsyms);
				fseek(file, syms->symoff, SEEK_SET);
				fread(symbols.list, sizeof(struct nlist), syms->nsyms, file);

				stringtbl = (char *) malloc(syms->strsize);
				//strtbl_len = syms->strsize;
				fseek(file, syms->stroff, SEEK_SET);
				fread(stringtbl, 1, syms->strsize, file);

				//printf("table: %X - %X\n", syms->symoff, syms->symoff+ syms->nsyms * sizeof(struct nlist));
				//printf("strings: %X - %X\n", syms->stroff, syms->stroff + syms->strsize);
				/*
				for(int y = 0; y < syms->nsyms; y++){
					char* name = getString(symbols.list[y].n_un.n_strx);
						if(strstr(name, "cGAMEMAIN") != NULL)
							printf("%X (%X): %s    %X\n", y, symbols.list[y].n_value, name, symbols.list[y].n_type);
				}*/
				
			}
			break;
		case LC_DYSYMTAB:
			{
				//printf("Dynamic Symbols\n-------------------------------\n");
				dysymtab_command * dysyms = (dysymtab_command *) p;
				//printf("",dysyms->


				/*
				dylib_module* modules = (dylib_module *) malloc(sizeof(dylib_module) * dysyms->nmodtab);
				fseek(binary, dysyms->modtaboff, SEEK_SET);
				fread(modules, sizeof(dylib_module), dysyms->nmodtab, binary);

				for(int y = 0; y < dysyms->nmodtab; y++){
					printf("%s\n", getStringFromTable(strtbl, modules[y].module_name, strtbl_len));

				}

				dylib_table_of_contents* toc = (dylib_table_of_contents *) malloc(sizeof(dylib_table_of_contents) * dysyms->ntoc);
				fseek(binary, dysyms->tocoff, SEEK_SET);
				fread(modules, sizeof(dylib_table_of_contents), dysyms->ntoc, binary);

				free(modules);
				free(toc);
				
				*/

				/*_nlist* indsyms = (_nlist *) malloc(sizeof(_nlist) * dysyms->nindirectsyms);
				fseek(binary, dysyms->indirectsymoff, SEEK_SET);
				fread(indsyms, sizeof(_nlist), dysyms->nindirectsyms, binary);

				for(int y = 0; y < dysyms->nindirectsyms; y++){
					//if(indsyms[y].n_un.n_strx == 0x1639){
					
					char* name = getStringFromTable(strtbl, indsyms[y].n_desc, strtbl_len);
					//indsyms[y].
						//if(strstr(name, "ExecClear") != NULL)
					if(name != strtbl)
							printf("%X (%X): %s    %X\n", indsyms[y].n_value, indsyms[y].n_un.n_strx, name, indsyms[y].n_type);

						//00100100
					//}
				}

				free(indsyms);
				
				*/

			}
			break;
		case LC_FUNCTION_STARTS:
			{
				func_starts = (linkedit_data_command *) p;
			}
			break;
		default:
			break;
		}

		p += cmd->cmdsize;

	}

	analyzeFunctions();
}


void mach_o::analyzeFunctions(){
	char* data = (char*) malloc(func_starts->datasize);
	fseek(file, func_starts->dataoff, SEEK_SET);
	fread(data, 1, func_starts->datasize, file);

	//Index into symbol table of last read symbol
	int isym = -1;
	int i;

	nfunctions = 0;

	int read = 0;
	int address = 0;
	int val = 0;
	char * buf = data;
	while(read < func_starts->datasize){
		int ret = read_uleb128(buf, &val);
		address += val;

		buf += ret;
		read += ret;
		

		//Make function entry passed on start address

		if(nfunctions > 0){
			if(functions[nfunctions - 1].offset == address -  1)
				continue;

			functions[nfunctions - 1].size = (address - 1) - functions[nfunctions - 1].offset; 
		}

		functions = (function *) realloc(functions, sizeof(function) * ++nfunctions);
		functions[nfunctions - 1].offset = address - 1;
		functions[nfunctions - 1].size = 0;

		//Just incase the function can't be linked to a symbol
		//TODO: Do more of the above comment
		functions[nfunctions - 1].name = 1;





		//Start linking to symbols
		i = ++isym + 1;
		do{
			if((symbols.list[i].n_type & N_STAB) != 0){

				if(resolveVirtualAddress(symbols.list[i].n_value) == address - 1){

					/* TODO: Deal with there being multiple symbols per function: EVENTUALLY remove this check and just go through the entire symbol list */
					if(symbols.list[i].n_un.n_strx != 1){
						functions[nfunctions - 1].addr = symbols.list[i].n_value;
						functions[nfunctions - 1].name = symbols.list[i].n_un.n_strx;
						functions[nfunctions - 1].section = symbols.list[i].n_sect;

						//Debug stuff for Puzzles and Dragons
						//char* name = getString(symbols.list[i].n_un.n_strx);
						//if(strlen(name) > 1){
						//	if(strstr(name, "cGAMEMAIN") != NULL)
						//		printf("%s\n", name);
						//}
						break;
					}
				}
			}

			i++;
			if(i >= symbols.cmd->nsyms)
				i = 0;
		} while(i != isym + 1);

		isym = i;


	}

	free(data);

}


mach_o::~mach_o(){

	free(this->commands);
	free(this->symbols.list);
	free(this->stringtbl);
}


char* mach_o::getString(int index){
	return this->stringtbl + index;
}


section* mach_o::getSection(int index){
	int count = 1;
	for(int x = 0; x < nsegments; x++){
		if(count  + segments[x]->nsects < index){
			count += segments[x]->nsects;
		}
		else{
			return &segments[x]->sections[index - count]; 
		}
	}
	return NULL;
}

/* Returns the file offset of a virtual memory address or null if it is not in the file */
int mach_o::resolveVirtualAddress(int vaddr){
	for(int x = 0; x < nsegments; x++){
		if(segments[x]->vmaddr + segments[x]->vmsize > vaddr){
			//Check that the address is allocated in the file
			if(segments[x]->vmaddr + segments[x]->filesize <= vaddr)
				break;

			return  segments[x]->fileoff + (vaddr - segments[x]->vmaddr);
		}
	}
	return NULL;
}