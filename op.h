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

#ifndef _OPEN_PATCHER_
#define _OPEN_PATCHER_

#include <stdio.h>
#include <stdlib.h>
#include <regex>
#include <map>
#include "tinyxml2.h"
#include "mach-o.h"

using namespace tinyxml2;


enum LOG_LEVEL{
	INFO = 0,
	VERBOSE, //Use this for any logging in handlers. INFO should be only used if absolutely necessary (users do not need to know handler internals)S
	WARNING,
	ERROR     //Use this when loging to indicate that something has gone terribly wrong

};

/* Always use the log function in the handler function */
/* This is just here to globalize the calls so that different output streams can be implemented */
void GLOBAL_LOG(const char * name, LOG_LEVEL lvl, char * msg, va_list args );


/* TODO: Change all the maps to use std:string */
class map_cstring_compare
{
public:
	bool operator()(const char* one,const char* two) { 
		if(one == NULL || two == NULL) return false;
		return strcmp(one,two) > 0; 
	};
};

/* The environment of variables sent to the handler during load */
class MOD_ENV{
public:

	/* TODO: Have this initialized by each handler that needs it */
	mach_o *file;

	/* Common interface to open app files. This way remote files can be appropriately retrieved and flushed later */
	/* All file handles will be rb+ */
	FILE *fopen(const char* filename);

	/* each handler can access variables defined in the XML config file */
	/* generally you do NOT need to use this function. just use the eval function on any parameters you get from the XML to make sure that any variable references are replaced */
	char* getVar(const char* name);
	
	void setVar(const char* name, char* value);
	void clearVars();

	/* Substitues in any variables used in the string (kind of like sprintf) */
	/* Handlers should use this on variable attributes */
	bool eval(const char *input, char* out, int bufSize);
	bool eval(const char *input, uint32_t* out);


private:
	std::map<const char*, char*, map_cstring_compare> _vars;
};




/* Inherit from this class in order to implement a new module into the patcher e.g: handle specific file format, packet filter... */
/* Each handler must have a unique patch type ma,e that identifies it e.g: the code editor is identified by is <patch type="code">settings...</patch>*/
class patch_handler{
public:
	//TODO: have this return an error type
	virtual bool handle(XMLElement *patch) = 0;

	/* Handlers are loaded once per handled application */
	/* MOD_ENV parameter should be used for variable resolution, io, and other global functionality */
	virtual void load(MOD_ENV* env) = 0;

	/* Make sure this returns the name of your handler */
	/* This should be the same as your unique tag type */
	virtual const char* name() = 0;
	
	/* Fairly obvious. Auto appends handler name, datetime, etc. */
	void log(LOG_LEVEL lvl, char* msg, va_list args){ GLOBAL_LOG(this->name(), lvl, msg, args); };
	void log(LOG_LEVEL lvl, char* msg, ...){ va_list args; va_start(args, msg); this->log(lvl, msg, args); };
	
	void log(char* msg, ...){ va_list args; va_start(args, msg); this->log(LOG_LEVEL::VERBOSE, msg, args); }; 

};

#endif
