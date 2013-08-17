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

#include "code_handle.h"

patch_handler* code_handle_init(){ return (patch_handler *)new code_handle();  };
void code_handle_destroy(patch_handler* h){ delete (code_handle *)h; };


function *code_handle::findFunc(const char *nclass, const char *nfunc){
	if(nfunc == NULL){
		return NULL;
	}

	int lclass;
	if(nclass != NULL){
		lclass = strlen(nclass);	
	}
	int lfunc = strlen(nfunc);

	function* func = NULL;
	for(int x = 0; x <  env->file->nfunctions; x++){
		char* fname = env->file->getString(env->file->functions[x].name);
		//__ZN9cGAMEMAIN19_gamePhaseInitClearEv

		bool match = false;
		if(nclass != NULL){
			//Too small to contain a prefix, numbers, and a class/func name
			if(strlen(fname) < 8)
				continue;

			fname += 4;

			int clen = strtol(fname, &fname, 10);
			if(clen != lclass){
				continue;
			}
			//Taken care off by strtol
			//fname += (int)ceil(log10(clen));
			if(strncmp(fname, nclass, clen) != 0){
				continue;
			}
			fname += clen;

			int flen = strtol(fname, &fname, 10);
			if(flen != lfunc){
				continue;
			}
			//fname += (int)ceil(log10(flen));
			if(strncmp(fname, nfunc, flen) != 0){
				continue;
			}

			
		}
		else{
			if(strcmp(fname, nfunc) != 0){
				continue;	
			};
		}
		
		func =  &env->file->functions[x];
		break;
	}

	return func;
};


void code_handle::set_reg(uint32_t val, int reg){
	if(val <= 0xFF){ //Use THUMB 16
		strm->write((uint16_t)(0x2000 + val)); //0x0120 mov r0, 1
	}
	else{ //THUMB 32 mov

		//1 1 1 1 0 i 1 0    0 1 0 0 imm4    0 imm3 Rd4    imm8    : mov

		int lVal = val & B32(00000000,00000000,11111111,11111111);
		int i =    (lVal & B16(00001000, 00000000)) << 15;
		int imm4 = (lVal & B16(11110000, 00000000)) << 4;
		int imm3 = (lVal & B16(00000111, 00000000)) << 4;
		int imm8 = (lVal & B16(00000000, 11111111));
		
		uint32_t x = (uint32_t)(B32(11110010,01000000,00000000,00000000) |imm4|i|imm3|imm8  | (reg << 8) );

		strm->write((uint32_t)(B32(11110010,01000000,00000000,00000000) |imm4|i|imm3|imm8  | (reg << 8) ) );
	}

	//TODO: This should check the number of bits set, not the value because sometimes it could be negative
	if(val > 0xFFFF){ //Need upper half
		//1 1 1 1 0 i 1 0    1 1 0 0 imm4     0 imm3 Rd4     imm8    : movt upper
		//imm16 = imm4:i:imm3:imm8
		int tVal = (val & B32(11111111,11111111,00000000,00000000)) >> 16;
		int i =    (tVal & B16(00001000, 00000000)) << 15;
		int imm4 = (tVal & B16(11110000, 00000000)) << 4;
		int imm3 = (tVal & B16(00000111, 00000000)) << 4;
		int imm8 = (tVal & B16(00000000, 11111111));

		uint32_t x = (uint32_t)(B32(11110010,11000000,00000000,00000000) |imm4|i|imm3|imm8  | (reg << 8) );

		strm->write((uint32_t)(B32(11110010,11000000,00000000,00000000) |imm4|i|imm3|imm8  | (reg << 8) ) );
	}
}


bool code_handle::handle(XMLElement *patch){
	//check if null
	//std::string str(patch->Attribute("function"));
	
	
	const char *nclass = patch->Attribute("class");
	const char *nfunc = patch->Attribute("function");
	
	function *func = this->findFunc(nclass, nfunc);
	
	if(func == NULL){
		this->log(LOG_LEVEL::ERROR, "Function %s::%s was not found", nclass, nfunc);
		return false; 
	}

	strm->gotoFunc(func);
	this->log("Entered function %s::%s", nclass, nfunc);


	XMLElement* cmd = patch->FirstChildElement();
	while(cmd != NULL){
		const char* cname = cmd->Name();
				
		if(strcmp(cname, "find") == 0){
			//Switch between different search methods
			const char* op = cmd->Attribute("op");
			if(op == NULL){
				this->log("No operation on find command");
				return false;
			}

			bool forwards = true;
			if(cmd->Attribute("dir") != NULL){
				if(strcmp("backward", cmd->Attribute("dir")) == 0){
					forwards = false;
					this->log("Search direction is backwards");
				}
			}

			//TO GET THIS TO WORK, I NEED TO MAKE SURE THE PARENTHESISES ARE INCLUDED AND I NEED A 'currentInstruction' function in codestream to flip the halfwords
			if(strcmp(op, "call") == 0){

				function* f = findFunc(cmd->Attribute("class"), cmd->Attribute("function"));
				bool found = false;

				//1 1 1 1 0 S imm10 1 1 J1 1 J2 imm11      : BL
				//I1 = NOT(J1 EOR S); I2 = NOT(J2 EOR S);
				//imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
				//toARM = FALSE;
				do{
				if(strm->opSize == sizeof(uint32_t)){
					uint32_t instr = strm->currentInstruction;
					/*                  Bitmask                                              Set Bits              */
					if((instr & B32(11111000,00000000,11010000,00000000)) == B32(11110000,00000000,11010000,00000000)){
						
						int s = (instr & B32(00000100,00000000,00000000,00000000)) >> 26;
						int j1 =(instr & B32(00000000,00000000,00100000,00000000)) >> 13;
						int j2 =(instr & B32(00000000,00000000,00001000,00000000)) >> 11;
						int i1 = !(j1 ^ s) & 1;
						int i2 = !(j2 ^ s) & 1;

						uint32_t imm32 = (s ? B32(11111111,00000000,00000000,00000000) : 0) /* Sign Extend */
										| (i1 << 23)
										| (i2 << 22)
										| ((instr & B32(00000011,11111111,00000000,00000000)) >> 4)  //imm10
										| ((instr & B32(00000000,00000000,00000111,11111111)) << 1); //imm11

						
						if((strm->pc + imm32 + strm->opSize /* ? */) == f->addr){
							found = true;
							this->log("Found call to %s::%s", cmd->Attribute("class"), cmd->Attribute("function"));
							break;
						}

					}
				}
				} while(forwards? strm->nextInstruction() : strm->backInstruction());

				if(!found){
					this->log(LOG_LEVEL::ERROR, "Could not find call to function %s::%s", cmd->Attribute("class"), cmd->Attribute("function") );
					return false;
				}


			}
			else if(strcmp(op, "return") == 0){
				bool found = false;

				//1 1 1 1 0 S imm10 1 1 J1 1 J2 imm11      : BL
				//I1 = NOT(J1 EOR S); I2 = NOT(J2 EOR S);
				//imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
				//toARM = FALSE;
				do{
					if(strm->opSize == sizeof(uint16_t)){
						/* TODO: Make the return finder more robust */
						if(*(uint16_t *)strm->ip == 0xbdf0){
							found = true;
							this->log("Found an early return from the function");
							break;
						}
					}
				} while(forwards? strm->nextInstruction() : strm->backInstruction());


				if(!found){
					this->log(LOG_LEVEL::ERROR, "Could not find a return before the end of the function");
					return false;
				}

			}
			else if(strcmp(op, "hex") == 0){

			}
			else{
				//Fatal: No such action available
				this->log(LOG_LEVEL::ERROR, "Invalid find command");
				return false;
			}

		}
		else if(strcmp(cname, "return") == 0){
			if(cmd->Attribute("value") != NULL){
				uint32_t val;
				if(!this->env->eval(cmd->Attribute("value"), &val)){
					//Fatal: Could not parse argument
					this->log(LOG_LEVEL::ERROR, "Could not evaluate '%s'", cmd->Attribute("value"));
					return false;

				}
				set_reg(val, 0);
				this->log(LOG_LEVEL::VERBOSE, "Setting return value to %d", val);
			}
			strm->write((uint16_t)0x4770); //0x7047: BX LR
			this->log(LOG_LEVEL::VERBOSE, "Function will now return");
		}
		else if(strcmp(cname, "set") == 0){
			if(cmd->Attribute("return") != NULL){
				uint32_t val;

				//TODO: Error check the 'eval' function below
				this->env->eval(cmd->Attribute("return"), &val);

				set_reg(val, 0);
				this->log("Set the return value register to %d", val);
			}

		}
		else if(strcmp(cname, "nop") == 0){
			if(strm->opSize == sizeof(uint16_t))
				//1 0 1 1 1 1 1 1 0 0 0 0 0 0 0 0
				strm->write((uint16_t)B16(10111111, 00000000));
			else
				//1 1 1 1 0 0 1 1 1 0 1 0 (1)(1)(1) (1) 1 0 (0) 0 (0) 0 0 0 0 0 0 0 0 0 0 0
				strm->write((uint32_t)B32(11110011, 10101111, 10000000, 00000000));

			this->log("Write NOP over the current operation");
		}
		else{
			this->log(LOG_LEVEL::ERROR, "Could not handle the command '%s'", cname);
			return false;
		}

		cmd = cmd->NextSiblingElement();
	}

	strm->flush();
	return true;
};

void code_handle::load(MOD_ENV* env){
	this->env = env;
	this->strm = new codestream(this->env->file);
	
};
