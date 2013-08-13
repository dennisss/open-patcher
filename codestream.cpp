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


codestream::codestream(mach_o *bin){
	this->binary = bin;
	this->modeTHUMB = false;
	this->ip = 0;
	this->pc = 0;
	this->instruction_buffer = NULL;
	this->buf_offset = 0;
	this->buf_size = 0;
	this->flushed = true;
	this->alignment = 0;
	this->opSize = 0;
	this->currentInstruction = 0;
}

codestream::~codestream(){
	free(this->instruction_buffer);
}

bool codestream::gotoFunc(function *func){
	if(!flushed){
		flush();
	}

	fseek(binary->file, func->offset, SEEK_SET);

	/* Give this whole buffer from file stuff its own function */
	instruction_buffer = (char *)realloc(instruction_buffer, func->size);
	buf_size = func->size;
	buf_offset = func->offset;

	pc = func->addr;

	if(fread(instruction_buffer, func->size, 1, binary->file) != 1){
		return false;
	}

	ip = instruction_buffer;
	alignment = 0;
	opSize = 0;

	uint16_t *instruction = (uint16_t *)ip;

	//Need to find a better way of detecting THUMB vs ARM mode

	//if(*instruction == 0xb5f0){ //Thumb "push" all registers
	modeTHUMB = true;
	//	ip += sizeof(uint16_t);
	//}

	//Loads the first instruction
	if(!readInstruction()){
		return false;
	}

	return true;
}


bool codestream::readInstruction(){
	uint16_t halfword = *((uint16_t *)ip);

	//32bit or 16bit 
	if((halfword & B16(11100000,00000000)) == B16(11100000,00000000)){
		if((halfword & B16(11111000,00000000)) == B16(11100000,00000000))
			opSize = sizeof(uint16_t);
		else
			opSize = sizeof(uint32_t);
	}
	//16bit
	else{
		opSize = sizeof(uint16_t);
	}
	

	//Set the currentInstruction property
	if(opSize ==  sizeof(uint32_t)){
		uint32_t hw = halfword;
		uint32_t hw2 = *(((uint16_t *)ip) + 1);

		currentInstruction = hw2 + (hw << 16);
	}
	else{
		currentInstruction = halfword;
	}


	return true;
}

bool codestream::nextInstruction(){
	//Next instruction is out of bounds
	if(ip + opSize >= instruction_buffer + buf_size){
		return false;
	}
	
	ip += opSize;
	pc += opSize;

	alignment = (alignment + opSize) % sizeof(uint32_t);

	if(!readInstruction()){
		return false;
	}

	//It is the last instruction; it will not consider the return instruction as an instruction
	//TODO: Make sure the calling function can tell between the last instruction and an out of bounds one
	if(ip + opSize >= instruction_buffer + buf_size){
		return false;
	}

	return true;
}

bool codestream::backInstruction(){
	if(ip == this->instruction_buffer){
		return false;
	}

	/* Current instruction is the second of two 16bit ones */
	if(alignment != 0){
		ip -= alignment;
		pc -= alignment;
	}
	else{
		ip -= sizeof(uint32_t);
		pc -= sizeof(uint32_t);

		if(!readInstruction()) return false;

		/* Went too far */
		if(opSize == sizeof(uint16_t)){
			ip += opSize;
			pc += opSize;
		}

	}

	return readInstruction();
}


//Use for 16bit thumb instructions only
bool codestream::write(uint16_t instr){
	if(opSize == sizeof(uint32_t)){
		//Write NOP to second half to remove back instruction
		*(((uint16_t*) ip) + 1) = (uint16_t)B16(10111111, 00000000);
	}

	*((uint16_t*) ip) = instr;
	readInstruction();
	nextInstruction();
	flushed = false;
	return true;
};

//For writing 32bit Thumb2 instructions
bool codestream::write(uint32_t instr){
	if(alignment != 0){
		//Write NOP to correct the alignment
		write((uint16_t)B16(10111111, 00000000));
	}

	//halfwords are flipped
	int upper = instr >> 16;
	*((uint16_t*) ip) = (uint16_t)(upper);
	*((uint16_t*) (ip + 2)) = (uint16_t)instr;

	readInstruction();
	nextInstruction();
	flushed = false;
	return true;
};

void codestream::flush(){
	if(flushed){
		return;
	}

	fseek(binary->file, buf_offset, SEEK_SET);
	fwrite(instruction_buffer, buf_size, 1, binary->file);
	fflush(binary->file);

	flushed = true;
}
