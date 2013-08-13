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

#ifndef _MACH_O_H
#define _MACH_O_H

#ifdef __APPLE__
	#include <mach-o/fat.h>
	#include <mach-o/loader.h>
	#include <mach-o/nlist.h>
#else
//For use in OS's like Windows that lake these headers
	#include "mach-o/fat.h"
	#include "mach-o/loader.h"
	#include "mach-o/nlist.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>


/* Helper macros */
#define HEX__(n) 0x##n##LU
#define B8__(x) ((x&0x0000000FLU)?1:0) \
+((x&0x000000F0LU)?2:0) \
+((x&0x00000F00LU)?4:0) \
+((x&0x0000F000LU)?8:0) \
+((x&0x000F0000LU)?16:0) \
+((x&0x00F00000LU)?32:0) \
+((x&0x0F000000LU)?64:0) \
+((x&0xF0000000LU)?128:0)

/* User macros */
#define B8(d) ((unsigned char)B8__(HEX__(d)))
#define B16(dmsb,dlsb) (((unsigned short)B8(dmsb)<<8) \
+ B8(dlsb))
#define B32(dmsb,db2,db3,dlsb) (((unsigned long)B8(dmsb)<<24) \
+ ((unsigned long)B8(db2)<<16) \
+ ((unsigned long)B8(db3)<<8) \
+ B8(dlsb))

struct IFILE{
	FILE* file;
	int magic;
};

IFILE* ifopen(char* file);
void ifclose(IFILE* file);

//Currently only 32bit same endian binaries are supported

class fat{
public:
	fat(IFILE* file);
	~fat();

	fat_header* header;
	fat_arch* architectures;
	

};


struct segment: segment_command{
	section sections[];
};

//Virtual stream from working with files inside of FAT files
// and for abstracting a method of reading/writing at virtual memory addresses; 
/*class VSTREAM{


    void read();
	void write();
	uint32_t tell();
	void seek(uint32_t addr, int mode);

};*/

struct function{
	uint32_t name;
	uint32_t section;
	uint32_t addr;
	uint32_t size;
	uint32_t offset;
};

size_t read_uleb128(char* buf, int* value);

class mach_o{
	friend class codestream;
public:
	mach_o(IFILE* file);
	~mach_o();

	char* getString(int index);
	section* getSection(int index);
	int resolveVirtualAddress(int vaddr);

	mach_header header;
	encryption_info_command* encryption_info; //MAKE SURE THIS IS CHECKED BY PROGRAM
	
	/* Furthest level of segmentation provided by this class */
	function *functions;
	int nfunctions; 

	segment** segments;
	int nsegments;

	
	
private:

	FILE* file;
	
	char* commands;
	char* stringtbl;

	//Subroutine for creating a function list with functions starts data and symbols;
	void analyzeFunctions();
	
	linkedit_data_command* func_starts;

	/* Symbols will be analyzed internally */
	struct {
		symtab_command* cmd;
		struct nlist* list;
	}symbols;


};


class codestream{
public:
	codestream(mach_o *bin);
	~codestream();

	bool modeTHUMB;

	//These will return false and fail if reading outside of the current function or segment
	bool nextInstruction();
	bool backInstruction();


	bool gotoFunc(function *func);
	bool gotoSegment(segment* seg);
	

	//instruction pointer
	char* ip;
	//The current virtual address
	int pc;

	int opSize; //The number of bytes ocuppied by the ORIGINAL opcode: used to make sure old instructions are completely overwritten, if writing is done, or padded with NO OP 
	int currentInstruction; //The current instruction (only opSize of it should be parsed)

	bool write(uint16_t instr);
	bool write(uint32_t instr);

	void flush();


private:
	mach_o *binary;
	char *instruction_buffer;
	int buf_offset;
	int buf_size;
	bool flushed;
	int alignment; //The number of byted off from a word aligned offset

	bool readInstruction();
};


#endif
