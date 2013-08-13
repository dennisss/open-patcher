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

#include "op.h"


char* MOD_ENV::getVar(const char* name){
	if(this->_vars.find(name) == this->_vars.end()){
		return NULL;
	}
	return this->_vars[name];
}
	
void MOD_ENV::setVar(const char* name, char* value){
	this->_vars[name] = value;
}

void MOD_ENV::clearVars(){
	this->_vars.clear();
}

bool MOD_ENV::eval(const char *input, char* out, int bufSize){
	int length = strlen(input);
	int offset = 0;
	char namebuf[64];

	/* '+1' because we need a null terminating byte */
	if(length + 1 > bufSize){
		return false;
	}

	for(int x = 0; x < length; x++){
		if(input[x] == '$'){
			int i = 0;
			for(x = x + 1; input[x] != '$'; x++){
				namebuf[i] = input[x];
				i++;
			}
			namebuf[i] = NULL;

			char* val = this->getVar(namebuf);
			
			if(val == NULL){
				return false;
			}

			int valsize = strlen(val);

			memcpy(out + offset, val, valsize);
			offset += valsize;
		}
		else{
			out[offset] =  input[x];
			offset += 1;

			if(offset + 1 > bufSize){
				return false;
			}
		}

	}

	out[offset] = NULL;

	return true;
}

bool MOD_ENV::eval(const char *input, uint32_t* out){
	char buf[256];
	if(!this->eval(input, buf, 256)){
		return false;
	}
	char* ep;
	long val = strtol(buf, &ep, 0);

	if(ep == buf){
		return false;
	}

	*out = val;

	return true;
}
