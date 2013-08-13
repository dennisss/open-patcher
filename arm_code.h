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

//Defines details about the arm instruction set + THUMB(2)

#ifndef _ARM_CODE_
#define _ARM_CODE_

enum sets{
	ARM = 0,
	
	//With things like this, the actual known target CPU architecture should be checked in order to determine which set is being used
	THUMB,
	THUMB2,
	
	NEON,
	VFP
};

struct instruction{
	sets type;
	size_t size;
	char *block;
};

#endif