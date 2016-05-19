#include <stdio.h>
#include <string.h>
#include <regex.h>
#include "afsadm.h"

struct group *find_grp(char *grp);

/****************************************************************************/

struct group *grp_table;	/* table of groups 		*/
struct group *actgrp;		/* pointer to actual group 	*/

struct command *cmd_table;	/* table of commands 		*/
struct command *actcmd;		/* pointer to actual command	*/

extern int debug;

/*********************************************************************
 *
 * Create new group in grptable, set pointer to actual grp
 *
 *********************************************************************/
int create_group(char *name) {
	struct group *gp;
	struct group *lastgrp = NULL;

#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: create_group(%s)\n", name);
#endif

	/* Check duplicity */
	for (gp = grp_table; gp != NULL; gp = gp->nextgrp) {
		lastgrp = gp;
		if (strcmp(gp->grpname, name) == 0)
			return(F_GRPEXISTS);
	}

	if ((gp = malloc(sizeof(struct group))) == NULL)
		return(F_NOMEM);

	if ((gp->grpname = malloc(sizeof(char) * (strlen(name) + 1))) == NULL)
		return(F_NOMEM);

	strcpy(gp->grpname, name);

	/* Linked list */
	if (lastgrp != NULL)
		lastgrp->nextgrp = gp;

	/* Initialize structure */
	gp->nextgrp = NULL;
	gp->membertable = NULL;
	gp->lastmember = 0;
	gp->memnum = 0;

	/* Set actual group */
	actgrp = gp;

	/* First entry in grp_table ? */
	if (grp_table == NULL)
		grp_table = gp;

	return 0;
}

/*********************************************************************
 *
 * Make principalname/group a member of actual group
 * ( If membername already exists in grptable => nested group )
 *
 *********************************************************************/
int add_to_group(char *membername) {
	struct member *mem;

#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: add_to_group %s member %s [%d]\n", actgrp->grpname, member, actgrp->memnum + 1);
#endif

	if ((mem = malloc(sizeof(struct member))) == NULL)
		return F_NOMEM;

	if ((mem->memname = malloc((strlen(membername) + 1) * sizeof(char))) == NULL)
		return F_NOMEM;

	strcpy(mem->memname, membername);
	mem->nextmem = NULL;
	if (find_grp(membername)) {
#ifdef _DEBUG_
		syslog(LOG_DEBUG, "Debug: Nested group %s in %s\n", membername, actgrp->grpname);
#endif
		mem->memtype = M_GROUP;
	} else
		mem->memtype = M_PRINCIPAL;

	/* Add to linked list */
	if (actgrp->membertable == NULL) {
		actgrp->membertable = mem;
		actgrp->lastmember  = mem;
	} else {
		(actgrp->lastmember)->nextmem = mem;
		actgrp->lastmember = mem;
	}

	/* Counter */
	actgrp->memnum++;
	return 0;
}

/*********************************************************************
 *
 * Create new command entry in cmdtable
 *
 *********************************************************************/
int create_command(char *cmdid) {
	struct command *cp;
	struct command *lastcmd = NULL;

#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: create_command(%s)\n", cmdid);
#endif


	/* Check duplicity */
	for (cp = cmd_table; ; cp = cp->nextcmd) {
		if (cp == NULL)
			break;
		lastcmd = cp;
		if (strcmp(cp->cmdid, cmdid) == 0)
			return F_COMMANDEXISTS;
	}

	if ((cp = malloc(sizeof(struct command))) == NULL)
		return F_NOMEM;

	if ((cp->cmdid = malloc(sizeof(char) * (strlen(cmdid) + 1)) ) == NULL)
		return F_NOMEM;

	strcpy(cp->cmdid, cmdid);

	/* Linked list */
	if (lastcmd != NULL)
		lastcmd->nextcmd = cp;
	cp->nextcmd = NULL;
	cp->help = NULL;
	cp->list = NULL;
	cp->grpnum = 0;
	cp->grptable = NULL;
	cp->regexptable = NULL;

	/* Set actual command */
	actcmd = cp;

	/* First entry in cmd_table? */
	if (cmd_table == NULL)
		cmd_table = cp;

	return 0;
}

/*********************************************************************
 *
 * Find groupname in grptable
 *
 *********************************************************************/
struct group *find_grp(char *grp) {
	struct group *p;

	for (p = grp_table; ; p = p->nextgrp) {
		if (p == NULL)
			return NULL;

#ifdef _DEBUG_
		syslog(LOG_DEBUG, "Debug: find_grp(%s), %s\n", grp, p->grpname);
#endif
		if (strcmp(grp, p->grpname) == 0) {
#ifdef _DEBUG_
			syslog(LOG_DEBUG, "Debug: Found groupname %s in grptable\n", grp);
#endif
			return p;
		}
	}
}


/*********************************************************************
 *
 * Add [group, regular expression] to actual command suite
 *
 *********************************************************************/
int add_regexp_to_comm(char *grp, char *regexp) {
	struct group *pg;
	char *pr;
	regex_t re;

#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: add_regexp_to_comm  %s grp = %s [%d]\n", actcmd->cmdid, grp, actcmd->grpnum + 1);
#endif

	if (regcomp(&re, regexp, REG_EXTENDED))
		return F_REGEXP;
	regfree(&re);

	if ((actcmd->grptable = realloc(actcmd->grptable, sizeof(struct group *) * (actcmd->grpnum + 1))) == NULL)
		return F_NOMEM;

	if ((actcmd->regexptable = realloc(actcmd->regexptable, sizeof(char *) * (actcmd->grpnum + 1))) == NULL)
		return F_NOMEM;

	if ((pr = malloc((strlen(regexp) + 1) * sizeof(char))) == NULL)
		return F_NOMEM;

	actcmd->regexptable[actcmd->grpnum] = pr;
	strcpy(pr, regexp);

	if ((pg = find_grp(grp)) == NULL)
		return F_NOGRP;
	actcmd->grptable[actcmd->grpnum] = pg;

	actcmd->grpnum++;
	return 0;
}

/*********************************************************************
 *
 *
 *
 *********************************************************************/
int add_to_cmd_list(char *cmd) {
	if(actcmd == NULL)
		return F_NOMEM;
	if (strlen(cmd) > 0 ) {
		if ((actcmd->list = malloc(sizeof(char) * (strlen(cmd) + 1))) == NULL)
			return F_NOMEM;
		strcpy(actcmd->list, cmd);
	} else if (debug)
		syslog(LOG_DEBUG, "Hidden command %s", actcmd->cmdid);

	return 0;
}

/*********************************************************************
 *
 * Set help string (usage) for actual command
 *
 *********************************************************************/
int add_to_cmd_help(char *hlp) {
	if (actcmd == NULL)
		return F_NOMEM;
	if((actcmd->help = malloc(sizeof(char) * (strlen(hlp) + 1))) == NULL)
		return F_NOMEM;
	strcpy(actcmd->help, hlp);

	return 0;

}

/*********************************************************************
 *
 * Create list of all groups
 *
 *********************************************************************/
char *get_list_of_groups(void) {
	struct group *pg;
	char *p = NULL;

	for (pg = grp_table; pg != NULL; pg = pg->nextgrp) {
		if (pg->grpname != NULL) {
			if (p == NULL) {
				p = malloc(sizeof(char) * (strlen(pg->grpname) + 2));
				p[0] = '\0';
			} else
				p = realloc(p, sizeof(char) * (strlen(p) + strlen(pg->grpname) + 2));
			if (p == NULL)
				break;
			strcat(p, pg->grpname);
			strcat(p, "\n");
		}
	}
	return p;
}

/*********************************************************************
 *
 * Create list of all available commands
 *
 *********************************************************************/
char *get_list_of_cmd(void) {
	struct command *pc;
	char *p = NULL;

	for (pc = cmd_table; ; pc = pc->nextcmd) {
		if (pc == NULL)
			break;
		if (pc->list != NULL) {
			if (p == NULL) {
				p = malloc(sizeof(char) * (strlen(pc->list) + 2));
				p[0] = '\0';
			} else
				p = realloc(p, sizeof(char) * (strlen(p) + strlen(pc->list) + 2));
			if (p == NULL)
				break;
			strcat(p, pc->list);
			strcat(p, "\n");
		}
	}
	return p;
}

/*********************************************************************
 *
 * Help (command usage)
 *
 *********************************************************************/
char *get_help(char *cmd) {
	struct command *pc;
	char *p = NULL;

	for (pc = cmd_table; ; pc = pc->nextcmd) {
		if (pc == NULL)
			break;
		if ((pc->list != NULL) && (pc->help != NULL) && (strcmp(cmd, pc->list) == 0)) {
			p = malloc(sizeof(char) * (strlen(pc->help) + 1));
			if (p != NULL)
				strcpy(p, pc->help);
			break;
		}
	}
	return p;
}

/*********************************************************************
 *
 * Is user a member of specified group entry?
 *
 *********************************************************************/
int chk_usergrp(char *user, struct group *grp) {
	struct member *pmem;
	struct group *pgrp;

	if (grp != NULL) {
		if (strcmp(grp->grpname, ANYUSERGRP) == 0)
			return CHK_OK;

		for (pmem = grp->membertable; pmem != NULL; pmem = pmem->nextmem) {
			switch (pmem->memtype) {
				case M_GROUP:
#ifdef _DEBUG_
					syslog(LOG_DEBUG, "Debug: nested test for membership");
#endif
					if ((pgrp = find_grp(pmem->memname)) == NULL) {
						syslog(LOG_DEBUG, "err: grp %s is not in grouptable!\n", pmem->memname);
						return CHK_NOGRP;
					} else {
						int result;

						result = chk_usergrp(user, pgrp);
						if (result != CHK_GRP)
							return result;
					}
				case M_PRINCIPAL:
					if (strcmp(user, pmem->memname) == 0)
						return CHK_OK;
					break;
				default:
					break;
			}
		}
	}
#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: User %s is not meber of group %s\n", user, grp->grpname);
#endif
	return CHK_GRP;
}

/*********************************************************************
 *
 * Check membership and all regexp in command suite
 *
 *********************************************************************/
int chk_cmd_regexp(char *cmd, struct command *cmdp, char *user) {
	int cnt;
	regex_t re;
	char *rstr;
	int lastresult = 0;

#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: Cmdid %s ~ %d regexps\n", cmdp->cmdid, cmdp->grpnum);
#endif
	for (cnt = 0; cnt < cmdp->grpnum; cnt++) {
#ifdef _DEBUG_
		syslog(LOG_DEBUG, "Debug: Check \"%s\"\n", cmdp->regexptable[cnt]);
#endif
		rstr = cmdp->regexptable[cnt];
		if (regcomp(&re, rstr, REG_EXTENDED | REG_NEWLINE)) {
			syslog(LOG_WARNING, "Invalid regexp %s in cmdgp %s\n", rstr, cmdp->cmdid);
			return CHK_REGEXP;
		}
		if (regexec(&re, cmd, 0, NULL, 0) == 0) {
			lastresult = (chk_usergrp(user, cmdp->grptable[cnt]));
			if (lastresult == CHK_OK)
				return lastresult;
		}
		regfree(&re);
	}

	/* if lastresult has been changed (cmd match regexp) - return it */
	if (lastresult != 0)
		return lastresult;

#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: Command \"%s\" doesn't match against cmdgrp %s\n", cmd, cmdp->cmdid);
#endif
	return CHK_REGEXP;
}

/*********************************************************************
 *
 * Authorization
 *
 *********************************************************************/
int chk_user_cmd(char *user, char *cmd) {
	struct command *pc;

	for (pc = cmd_table; pc != NULL; pc = pc->nextcmd) {
		switch (chk_cmd_regexp(cmd, pc, user)) {
			case CHK_OK:
				return CHK_OK;
			case CHK_GRP:
				return CHK_GRP;
			default:
				break;
		}
	}

#ifdef _DEBUG_
	syslog(LOG_DEBUG, "Debug: Command \"%s\" doesn't match against any cmdgrp\n", cmd);
#endif
	return CHK_REGEXP;
}
