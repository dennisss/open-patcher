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

/* COMPILE FOR 32BIT ONLY!!!!!!!!!! */
/* Has not been verified for 64bit builds */

#ifdef __APPLE

#include <mach/mach.h>

//for daemon stuff
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>

#endif

#include <string.h>

FILE* binary;

XMLDocument config;
XMLElement* root;

//For storing all the mod variables parsed out of the command line
std::map<const char *, std::map<const char*, char *, map_cstring_compare>, map_cstring_compare> CMD_VARS;
//All the main() flags and inputs
std::map<char*, char*, map_cstring_compare> CMD_ARGS;

#include "patchers/code_handle.h"

//Eventually allocate and load these dynamically per each application patched
code_handle ch;
void initHandles(MOD_ENV *env){
	ch.load(env);
}

bool bVERBOSE = false;
void GLOBAL_LOG(const char * name, LOG_LEVEL lvl, char * msg, va_list args ){
	time_t now;
	time(&now);

	char time_string[128];

	struct tm * p = localtime(&now);

	strftime(time_string, 1000, "%m/%d/%y %H:%M:%S", p);

	/* TODO: Eventually filter to various verbosity levels */

	char * condition = "NULL";
	switch(lvl){

	case LOG_LEVEL::INFO:
		condition = "INFO";
		break;
	case LOG_LEVEL::VERBOSE:
		if(!bVERBOSE){
			return;
		}
		condition = "VERB";
		break;
	case LOG_LEVEL::WARNING:
		condition = "WARN";
		break;
	case LOG_LEVEL::ERROR:
		condition = "ERR";
		break;
	}


	printf("[%s] %s: %s: ", time_string, name, condition);

	vprintf(msg, args);

	printf("\n");
}
void GLOBAL_LOG(LOG_LEVEL lvl, char * msg, ...){
	va_list args;
	va_start(args, msg);
	GLOBAL_LOG("MAIN", lvl, msg, args);
	va_end(args);

}
void GLOBAL_LOG(char * msg, ...){
	va_list args;
	va_start(args, msg);
	GLOBAL_LOG("MAIN", LOG_LEVEL::INFO, msg, args);
	va_end(args);

}



void loadFile(char *file){
	IFILE* f = ifopen(file);

	//switch between mach-o and fat
	if(f->magic != MH_MAGIC){
		GLOBAL_LOG(LOG_LEVEL::ERROR, "Looks like the file is in an unimplemented format. Try thining it to a MACH-O format");
		return;
	}
	

	mach_o m(f);
	
	if(m.encryption_info->cryptid == 1){
		GLOBAL_LOG(LOG_LEVEL::ERROR, "The code is encrypted and no source of decrypted memory is available. Please manually crack the app.");
		return;
	}


	MOD_ENV env;
	env.file = &m;

	char* delim;
	delim = strrchr(file, '\\');
	if(delim == NULL){
		delim = strrchr(file, '/');
		if(delim == NULL){
			//Assume same directory
			delim = file;
			*delim = '/';
		}
	}

	*(delim + 1) = NULL;
	env.app_directory = file;
	//env._vars.clear;

	initHandles(&env);
	
	XMLElement* el = root->FirstChildElement("mod");
	while(el != NULL){

		XMLElement* name = el->FirstChildElement("name");
		const char* key = el->Attribute("key");
		if(CMD_VARS.find(key) != CMD_VARS.end())
		{

			GLOBAL_LOG("Applying %s", name->GetText());

			//Map all the variables to their values if possible
			XMLElement* var = el->FirstChildElement("var");
			while(var != NULL){
				const char* sym = var->Attribute("sym");
				if(sym == NULL){
					GLOBAL_LOG(LOG_LEVEL::ERROR, "Variable has no 'sym' abbreviation");
					return;
				}

				if(CMD_VARS[key].find(sym) != CMD_VARS[key].end()){
					//Set value from args
					env.setVar(sym, CMD_VARS[key][sym]);

				}
				else if(false){
					//Use default value
				}
				else{
					GLOBAL_LOG(LOG_LEVEL::ERROR, "Variable '%s' has no value", sym);
					//Fatal Error: variable has no value
				}
				var = var->NextSiblingElement("var");
			}

			XMLElement* patch = el->FirstChildElement("patch");
			while(patch != NULL){
				//check the 'type' attribute of the patch
			
				patch_handler* h;

				const char *type = patch->Attribute("type");
				if(strcmp(type, "code") == 0){
					h = (patch_handler *)&ch;
				}
				else if(strcmp(type, "memory") == 0){
					//make sure MH_PIE flag is not set 
					//or eventually compensate for this if the program is running on the device
				}
				else if(strcmp(type, "plist") == 0){


				}

				if( !h->handle(patch) ){
					printf("\n");
					GLOBAL_LOG("Patching failed. Note: This may be because the patch was already applied before");
					return;
				}

				patch = patch->NextSiblingElement("patch");
			}

			env.clearVars();
		}
		else
			GLOBAL_LOG("Skipping %s", name->GetText());

		el = el->NextSiblingElement("mod");
	}

	printf("\n");
	GLOBAL_LOG("Success!");
}

void printUsage(){
	printf("Usage:\n");
	printf("    As a file patcher:\n");
	printf("        op -c=<patch_config_file.xml> -f=<*.app directory> (--MODKEy -varname=value... --MOD2 ...\n");

	//Need to make a way to pass vars into the daemons
	printf("    As a background task:\n");
	printf("        op -d -c=/<patch_config_directory\n");
	printf("\n");
	printf("Arguments:\n");
	//printf("    -s: SSH Mode- automatically connect to jailbroken iDevice, find app binary, decrypt if necessary, patch, resign, etc.\n");
	//printf("                  This mode requires 'ldone', 'gdb', and 'openssh', to be installed from cydia. \n");
	//printf("\n");
	//printf("    -f: Local file- uses local decrypted/cracked binaries (<APPNAME> not <APPNAME>.app files).\n");
	//printf("                    You are responsible for reinjecting, resigning, and chmoding/chowning these your self.\n");
	//printf("        -fi: Use this when running on an iPhone. This will allow on device modification and cracking.\n");
	//printf("\n");
	
	printf("    -c: Specify config XML file path.\n");
	printf("        (When in daemon mode, this is a path to a directory containing all the config files)\n");
	printf("    -f: Specify app data path \n");
	printf("        (Required unless -c points to a directory)\n");
	printf("    -v: Verbose output: Useful for debugging patches\n");
	printf("    -l: List cheats available in the config file (requires -c be a file).\n");
	printf("\n");
	printf("    -d: Daemon Mode (Linux only)- Automatically run in the background, and attach to apps when they are running.\n");
	printf("                     This mode allows for on the fly memory editing. Because all the code is in memory,\n");
	printf("                     no modifications to the actual binary file are neccessary. This means no decrypting,\n");
	printf("                     no removing ASLR (we can compensate for this in code). Thus, conventional methods can\n");
	printf("                     not detect these hacks.\n");
	//Make this into a global folder
	printf("                     Place config files in each app's *.app folder. Name them as APPNAME.xml.\n");

	printf("\n");
	printf("\n");
	printf("    -x: Dev. Mode used for creating mods (Not yet implemented)\n");
	printf("\n    Note: FAT (multiarchitecture) binaries are supported but only the current device's/already decrypted architectures will be patched. \n");
}


void daemon(){
#ifdef __APPLE__

	/* Our process ID and Session ID */
	pid_t pid, sid;
	
	/* Fork off the parent process */
	pid = fork();
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}
	/* If we got a good PID, then
	we can exit the parent process. */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Change the file mode mask */
	umask(0);
	
	/* Open any logs here */        
	
	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		/* Log the failure */
		exit(EXIT_FAILURE);
	}
	
	/* Change the current working directory */
	if ((chdir("/")) < 0) {
		/* Log the failure */
		exit(EXIT_FAILURE);
	}
	
	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
        
	/* Daemon-specific initialization goes here */
	
	/* The Big Loop */
	while (1) {
		/* Do some task here ... */   
		sleep(30); /* wait 30 seconds */
	}
	exit(EXIT_SUCCESS);
#else
	GLOBAL_LOG(LOG_LEVEL::ERROR, "Try again on iOS");
#endif
}



/* Parses and splits the command line args into two groups: CMD_ARGS (for key-value pairs or flags) and CMD_VARS (for associative arrays (groups of key-values)) */
bool parseCmd(int argc, char *argv[])
{
	bool inArray = false;
	char* arrayKey;
	for(int x = 1; x < argc; x++){
		if(argv[x][0] == '-'){
			/* Array of args */
			/* Arrays are single dimensional */
			if(argv[x][1] == '-'){

				arrayKey = argv[x] + 2; // +2 eliminates the "--"
				if(strlen(arrayKey) == 0)
					return false;

				CMD_VARS[arrayKey] = std::map<const char*, char*, map_cstring_compare>();
				inArray = true;

			}
			else{
				char* val = strchr(argv[x] + 1, '=');
				
				if(val != NULL){
					*val = NULL; //Split the arg into two strings
					val += 1; //Eliminate the '='
				}
				else{
					val = "";
				}

				if(strlen(argv[x] + 1) == 0)
					return false;

				if(inArray){
					CMD_VARS[arrayKey][argv[x] + 1] = val;
				}
				else{
					CMD_ARGS[argv[x] + 1] = val;
				}

			}
		}
		else{
			return false;
		}
	}
	return true;
}


int main(int argc, char *argv[])
{
	printf("Open Patcher %d.%d-%d\nApplication modification and reverse engineering automation\n", VERSION_MAJOR, VERSION_MINOR, VERSION_REVISION);
	printf("-------------------------------------------------------------------\n\n");

	if(argc < 3){
		printUsage();
		return 0;
	}

	if(!parseCmd(argc, argv)){
		printUsage();
		return 0;
	}

	if(CMD_ARGS.find("v") != CMD_ARGS.end()){
		bVERBOSE = true;
	}

	char* configPath; 
	std::map<char*, char*>::iterator it = CMD_ARGS.find("c");
	int x = CMD_ARGS.count("c");
	if(it == CMD_ARGS.end()){
		GLOBAL_LOG(LOG_LEVEL::ERROR, "No configuration file(s) path specified. Cannot continue.");
		return 1;
	}
	configPath = CMD_ARGS["c"];

	//Daemon mode
	if(CMD_ARGS.find("d") != CMD_ARGS.end()){
		GLOBAL_LOG("Entering daemon mode...");
		daemon();
		return 0;
	}

	//Developer mode
	if(CMD_ARGS.find("x") != CMD_ARGS.end()){
		GLOBAL_LOG("Developer Mode Selected");
		GLOBAL_LOG(LOG_LEVEL::ERROR, "DEV MODE NOT YET IMPLEMENTED");
		return 1;
	}


	GLOBAL_LOG("Loading config file %s", CMD_ARGS["c"]);
	
	XMLError e = config.LoadFile(CMD_ARGS["c"]);
	if(e != XML_NO_ERROR){
		//TODO: Print more info on specific errors
		GLOBAL_LOG(LOG_LEVEL::ERROR, "Failed to load config file. Xml Error %d", e);
		return 1;
	}

	//TODO: Give the settings file its own class/api
	root = config.RootElement();
	if(root == NULL){
		GLOBAL_LOG(LOG_LEVEL::ERROR, "Failed to load config file. Missing root element");
		return 1;
	}
	if(strcmp("app", root->Name()) != 0){
		GLOBAL_LOG(LOG_LEVEL::ERROR, "Failed to load config file. Invalid root element");
		return 1;
	}

	GLOBAL_LOG(LOG_LEVEL::VERBOSE, "Configuration revision should be '%d'", CONFIG_REVISION);
	const char* config_rev = root->Attribute("configrevision");
	if(config_rev != NULL){
		int rev = atoi(config_rev);
		if(rev == 0){
			GLOBAL_LOG(LOG_LEVEL::ERROR, "Invalid configuration revision number");
			return 1;
		}
		if(rev != CONFIG_REVISION){
			GLOBAL_LOG(LOG_LEVEL::ERROR, "Configuration revision not supported by this program. Consider using a different version of the config file or a different version of this program.");
			return 1;
		}
	}
	else{
		GLOBAL_LOG(LOG_LEVEL::ERROR, "No configuration revision defined on the root element");
		return 1;
	}

	if(CMD_ARGS.find("l") != CMD_ARGS.end()){
		printf("LIST NOT YET IMPLEMENTED");
		return 0;
	}





	char* folder;
	if(CMD_ARGS.find("f") == CMD_ARGS.end()){
		GLOBAL_LOG(LOG_LEVEL::ERROR, "Please specify a folder containing the app files");
		return 1;
	}
	folder = CMD_ARGS["f"];


	char* file = NULL;

	//TODO: ... Look into the folder for the binary by lookinf up its name in the config file ...
	file = folder;

	/*GLOBAL_LOG("Backing up the original file as %s.bak", file);
	if(system("cp \"%s\" \"%s.bak\"", file, file) != NULL){
		GLOBAL_LOG(LOG_LEVEL::ERROR, "Error: Could not create a backup of the source file");
		exit(1);
	}*/
	
	loadFile(file);

	return 0;
}
