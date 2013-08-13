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

#ifndef _CODE_HANDLE_
#define _CODE_HANDLE_

#include "../op.h"
#include "../mach-o.h"

class code_handle : patch_handler{
public:
	code_handle(){};

	const char* name(){ return  "CODE"; };

	bool handle(XMLElement *patch);
	void load(MOD_ENV* env);

private:
	MOD_ENV* env;
	codestream* strm;

	function *findFunc(const char *nclass, const char *nfunc);
	void set_reg(uint32_t val, int reg);
};

#endif
