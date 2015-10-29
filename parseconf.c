#include <stdio.h>
#include <string.h>
#include "afsadm.h"

#define GETLINE(buff, MAX, fd) fgets(buff, MAX, fr)

/* Symbols */
#define END -1

#define IDENTIF 1
#define KEYWORD 2
#define LBRACE 3
#define RBRACE 4
#define HASH 5

#define STRING 98
#define NOSTRING 99

/* Keywords */
#define NUM_OF_KEY 3

#define DEFINE 0
#define GROUP 1
#define COMMAND 2
#define NO_KEY 9999
char *key_word[NUM_OF_KEY] = {"define", "group", "command"};

#define A_DEFINE 0
#define A_GROUP 1
#define A_COMMAND 2
#define A_LBRACE 3
#define A_RBRACE 4
#define A_IDENTIF 5
#define A_START 6
#define A_MEMBER 7
#define A_COMLINES 8
#define A_COMHELP 9 /* Short "command usage" and help */

#define M_WORD 0
#define M_STRING 1

int linenum;

/*****************************************************************/

#define is_symbol(a) if(strcmp(s, a) == 0)

/*********************************************************************
*
* Is it symbol or identifier?
*
*********************************************************************/
int symbol(char *s) {
	is_symbol("{")
	return LBRACE;
	is_symbol("}")
	return RBRACE;
	is_symbol("#")
	return HASH;
	return IDENTIF;
}

/*********************************************************************
*
* Test for keywords
*
*********************************************************************/
int is_keyword(char *s) {
	int i;

	for (i = 0; i < NUM_OF_KEY; i++)
		if (strcmp(s, key_word[i]) == 0)
			return i;
		return NO_KEY;
}


/*********************************************************************
*
* Read one word or "string" from file
*
*********************************************************************/
int read_word(FILE *fr, char *word, int mode) {
	static char line[MAXLINE];
	static char *p = NULL;
	int result;

	#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: Function read_word(), mode = %d\n", mode);
	#endif
	for (;;) {
		if (p == NULL) {
			if (GETLINE(line, MAXLINE, fr) <= 0)
				return END;
			p = line;
			linenum++;
			#ifdef _DEBUG_
			syslog(LOG_DEBUG, "Debug: Read line %d:%s", linenum, line);
			#endif
		}
		while(isspace(*p))
			p++;

		if (mode == M_STRING ) {
			char *start, *stop;

			start = stop = NULL;

			start = strchr(p, (int)'"');
			if(start != NULL)
				stop = strchr(start + 1, (int)'"');

			word[0] = '\0';
			if (start != NULL && stop != NULL) {
				*stop = '\0';
				strcpy(word, (start + 1));
				p = stop + 1;
				return STRING;
			} else
				return NOSTRING;
		} else {
			if ((sscanf(p, "%s", word) <= 0) || (result = symbol(word)) == HASH) {
				p = NULL;
				continue;
			} else {
				p += strlen(word);
#ifdef _DEBUG_
				syslog(LOG_DEBUG, "Debug: Word=%s, symbol=%d\n", word, result);
#endif
				return result;
			}
		}
	}
}

/*********************************************************************
*
* Grammar (recursive call)
*
*********************************************************************/
int read_object(FILE *fr, int action) {
	char word[MAXLINE];
	int symbol;
	int result;

	/* Read one word from file */
	symbol = read_word(fr, word, M_WORD);

	switch (action) {
		case A_START:
			if (symbol == END)
				break;
			if (symbol != IDENTIF)
				return F_PARSE;

			switch (is_keyword(word)) {
				case DEFINE: return read_object(fr, A_DEFINE);
				default: return F_PARSE;
			}

		case A_DEFINE:
			if (symbol != IDENTIF)
				return F_PARSE;
			switch (is_keyword(word)) {
				case GROUP: return read_object(fr, A_GROUP);
				case COMMAND: return read_object(fr, A_COMMAND);
				default: return F_PARSE;
			}
		case A_GROUP:
			if (symbol != IDENTIF)
				return F_PARSE;
			if (is_keyword(word) != NO_KEY)
				return F_GRPNAME;
#ifdef _DEBUG_
			syslog(LOG_DEBUG, "Debug: Create group %s\n", word);
#endif
			if (result = create_group(word))
				return result;

			symbol = read_word(fr, word, M_WORD);
			if (symbol != LBRACE)
				return F_PARSE;
			return read_object(fr, A_MEMBER);

		case A_COMMAND:
			if (symbol != IDENTIF)
				return F_PARSE;
			if (is_keyword(word) != NO_KEY)
				return F_COMMANDNAME;
#ifdef _DEBUG_
			syslog(LOG_DEBUG, "Debug: Create command %s\n", word);
#endif
			if (result = create_command(word))
				return result;

			symbol = read_word(fr, word, M_WORD);
			if (symbol != LBRACE)
				return F_PARSE;
			return read_object(fr, A_COMLINES);

		case A_COMLINES: {
			char *grp;

			if (symbol == RBRACE)
				return read_object(fr, A_COMHELP);
			if (symbol != IDENTIF)
				return F_PARSE;
			if (is_keyword(word) != NO_KEY)
				return F_COMGRP;

			if ((grp = malloc(strlen(word) + 1)) == NULL)
				return F_NOMEM;
			strcpy(grp, word);

			symbol = read_word(fr, word, M_STRING);

			if (symbol != STRING) {
				free(grp);
				return F_COMSTR;
			}
			if (result = add_regexp_to_comm(grp, word)) {
				free(grp);
				return result;
			}
#ifdef _DEBUG_
			syslog(LOG_DEBUG, "Debug: Add regexp [ grp = %s ] %s\n", grp, word);
#endif
			free(grp);
			return read_object(fr, A_COMLINES);

		}
		case A_MEMBER:
			if (symbol == RBRACE)
				return read_object(fr, A_START);

			if (symbol != IDENTIF)
				return F_PARSE;
			if (is_keyword(word) != NO_KEY)
				return F_MEMBER;
#ifdef _DEBUG_
			syslog(LOG_DEBUG, "Add to group %s\n", word);
#endif
			if (result = add_to_group(word))
				return result;
			return read_object(fr, A_MEMBER);

		case A_COMHELP:
			if (symbol != LBRACE)
				return F_PARSE ;
			if ((symbol = read_word(fr, word, M_STRING)) == STRING) {
				if (result = add_to_cmd_list(word))
					return result;
#ifdef _DEBUG_
				syslog(LOG_DEBUG, "Debug: Short usage is: %s\n", word);
#endif
			} else
				return F_COMSTR;

			if ((symbol = read_word(fr, word, M_STRING)) == STRING) {
				if (result = add_to_cmd_help(word))
					return result;
#ifdef _DEBUG_
				syslog(LOG_DEBUG, "Debug: Help is: %s\n", word);
#endif

			} else
				return F_COMSTR;

			if ((symbol = read_word(fr, word, M_WORD)) != RBRACE)
				return F_PARSE;
			return read_object(fr, A_START);

		default:
			return F_PARSE;

	}

	return 0;
}


/*********************************************************************
*
* Parse configfile
*
*********************************************************************/
int parse_config_file(cnf) {
	int result = 0;
	FILE *fr;

	linenum = 0;

	if ((fr = fopen(cnf, "r")) == NULL) {
		syslog(LOG_ERR, "Cannot open configuration file\n");
		return -1;
	}

	/* Create special group - anyuser */
	if ((result = create_group(ANYUSERGRP)) == 0) {
		/* Start parsing */
		result = read_object(fr, A_START);
	}

	/* Error messages */
	switch (result) {
		case F_PARSE:
			syslog(LOG_ERR, "Error parsing configuration file at line %d\n", linenum);
			break;
		case F_GRPNAME:
			syslog(LOG_ERR, "Invalid groupname at line %d\n", linenum);
			break;
		case F_GRPEXISTS:
			syslog(LOG_ERR, "Duplicated groupname at line %d\n", linenum);
			break;
		case F_MEMBER:
			syslog(LOG_ERR, "Invalid membername at line %d\n", linenum);
			break;
		case F_COMMANDNAME:
			syslog(LOG_ERR, "Invalid commanname at line %d\n", linenum);
			break;
		case F_COMMANDEXISTS:
			syslog(LOG_ERR, "Duplicated commandname at line %d", linenum);
			break;
		case F_COMGRP:
			syslog(LOG_ERR, "Invalid groupname in command definition at line %d\n", linenum);
			break;
		case F_COMSTR:
			syslog(LOG_ERR, "Quoted \"string\" expected at line %d\n", linenum);
			break;
		case F_NOMEM:
			syslog(LOG_ERR, "Cannot allocate memory\n");
			break;
		case F_NOGRP:
			syslog(LOG_ERR, "Group doesn't exist (line %d)\n", linenum);
			break;
		case F_REGEXP:
			syslog(LOG_ERR, "Invalid regexp at line %d\n", linenum);
			break;
		default:
			break;
	}

	fclose(fr);
	return result;
}
