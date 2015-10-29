#ifndef _AFSADM_H_
#define _AFSADM_H_

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <krb5.h>

#include <errno.h>

#ifndef krb5_xfree
#define krb5_xfree free
#endif

/*********************************************************************
 *
 * Protocol version, K5 service 
 * 
 *********************************************************************/

#define AFSADM_SERVICE "afsadm"
#define AFSADM_PORT "afsadm"
#define AFSADM_HOSTNAME "afsadm"
#define AFSADM_VERSION "1.0"

/*********************************************************************
 *
 * Configuration 
 * 
 *********************************************************************/

#ifndef AFSADMCONFIGNAME
#define AFSADMCONFIGNAME "afsadm.conf"
#endif

#ifndef AFSADMDIR
#define AFSADMDIR "/tmp/afsadm"
#endif




#define MAXLINE		 1024
#define ANYUSERGRP	"anyuser"

/*********************************************************************
 *
 * Structures 
 * 
 *********************************************************************/

#define		M_GROUP		0
#define		M_PRINCIPAL	1

struct member {			/* Member of group - group/principal */
	char *memname;
	int  memtype;		/* group/principal */
	struct member *nextmem;
} member;


struct group {			/* Group - name and list of members */
	char   *grpname;
	struct member *membertable;
	struct member *lastmember;
	int    memnum;
	struct group *nextgrp;	
} group;


struct command {
	char    *cmdid;
	int	grpnum;
	struct  group	**grptable;
	char    **regexptable;
	char    *list;
	char    *help;
	struct  command *nextcmd;
} command;


/*********************************************************************
 *
 * Error codes
 * 
 *********************************************************************/

#define F_PARSE		-5	/* Syntax error */
#define F_GRPNAME	-6	/* Invalid groupname (keyword) */
#define F_GRPEXISTS	-7	/* Groupname already exists */
#define F_MEMBER	-8	/* Invalid membername */
#define F_COMMANDNAME	-9	/* Invalid commandname */
#define F_COMMANDEXISTS -10	/* Command already exists */
#define F_COMGRP	-11	/* Invalid group in command def */
#define F_COMSTR	-12	/* "String" expected */
#define F_NOMEM		-13	/* No memory */
#define F_NOGRP		-14	/* Group doesn/t exist */
#define F_REGEXP	-15	/* Invalid regexp */

#define CHK_OK		0
#define CHK_GRP 	1
#define CHK_REGEXP	2
#define CHK_ERR		3
#define CHK_NOGRP	4

/*********************************************************************
 *
 * global structures, variables 
 * 
 *********************************************************************/

extern char *confdir;
extern int  debug;
extern struct group *grp_table;
extern struct command *cmd_table;

/*********************************************************************/

extern int create_group(char *name);
extern int create_command(char *cmdid);
extern int add_regexp_to_comm(char *grp, char *regexp);
extern int add_to_group(char *grp);
extern int add_to_cmd_list(char *cmd);
extern int add_to_cmd_help(char *hlp);

extern char *get_list_of_cmd(void);
extern char *get_list_of_groups(void);
extern char *get_help(char *cmd);

extern int chk_user_cmd(char *user, char *cmd);


/*********************************************************************
 *
 * Main functions 
 * 
 *********************************************************************/

extern int   parse_config_file(char *cfgfile);
extern int   do_command(krb5_context context, 
			krb5_keytab keytab, 
			krb5_principal me, 
			char *princ, 
			char *cmd, 
			char *cmddir);


/*********************************************************************
 *
 * AFS 
 * 
 *********************************************************************/
extern int k_hasafs(void);
extern int k_setpag(void);
extern int k_unlog(void);


#endif 		/*_AFSADM_H*/
