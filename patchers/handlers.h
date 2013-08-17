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

#ifndef _OP_HANDLERS_
#define _OP_HANDLERS_

/* patchers/handlers.h : This file does not contain any patcher/handler definitions. Rather it 
*                        contains a lookup table that tells the main program which handlers to call
*                        and how to use them.
*/

#include "../op.h"
/* Add includes to specific patchers here */
#include "code_handle.h"

/* End patcher includes */


/*  patch_handler*  patchname_handle_init()  */
typedef patch_handler* (*patch_handler_init)();

/*  void            patchname_handle_destroy()  */
typedef void (*patch_handler_destroy)(patch_handler* h);


struct HANDLER_ENTRY{
	patch_handler_init init;
	patch_handler_destroy destroy;
};

HANDLER_ENTRY HANDLERS[] = {
	{code_handle_init, code_handle_destroy}

	/* Additional entries for handlers go above this comment*/


};

#endif