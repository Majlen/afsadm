#include <krb5.h>
#include <com_err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "afsadm.h"

krb5_preauthtype *preauth = NULL;
krb5_preauthtype preauth_list[2] = { KRB5_PADATA_ENC_TIMESTAMP, -1 };

krb5_data tgtname = {
	0,
	KRB5_TGS_NAME_SIZE,
	KRB5_TGS_NAME
};



/*********************************************************************
 *
 * 0 - Help printed
 * 1 - Command
 *
 *********************************************************************/
int gethelp(char *str) {
	char *list;
	char *p;
	static char helpstr[] = "help [command]\nquit/exit";
	static char help[] = "help";

	if (strncmp(str, help, 4) == 0) {
		/* Skip word "help" */
		p = str + 4;
		while (isspace((int)*p))
			p++;

		if ((*p != '\0') && (list = get_help(p))) {
			if (write(1, list, strlen(list)) == -1)
				printf("Failed write to stdout.\n");
			free(list);
			return 0;
		} else {
			if ((list = get_list_of_cmd()) == NULL) {
				if (debug)
					syslog(LOG_DEBUG, "NULL cmdlist");
				if (write(1, helpstr, strlen(helpstr)) == -1)
					printf("Failed write to stdout.\n");
				return 0;
			}
			printf("%s%s", list, helpstr);
			free(list);
			return 0;
		}
	}
	return 1;
}


int do_command(krb5_context context, krb5_keytab keytab, krb5_principal me, char *princ, char *cmd, char *cmddir) {
	char *p;
	char *answer;
	static char answer_exec[] = "Cannot execute command.";
	static char answer_priv[] = "You are not privileged to execute this command.";
	static char answer_regexp[] = "Command doesn't match any allowed regexp.";
	int result;

	if (debug)
		syslog(LOG_DEBUG, "Principal %s is trying to execute command %s", princ, cmd);

	/* Replace \n with \0 */
	p = cmd;
	while (*p != '\0' && *p != '\n')
		p++;
	*p = '\0';

	if (gethelp(cmd) == 0)
		return 0;

	if ((result = chk_user_cmd(princ, cmd)) != 0) {
		switch(result) {
			case CHK_GRP:
				answer = answer_priv;
				break;
			case CHK_REGEXP:
				answer = answer_regexp;
				break;
			default:
				answer = answer_exec;
		}
		if (debug)
			syslog(LOG_DEBUG, "%s", answer);
		if (write(1, answer, strlen(answer)) == -1)
			printf("Failed write to stdout.\n");
		return 0;
	} else {
		char *localcmd, *pathenv;
		char ccname[255];
		krb5_ccache ccache;
		krb5_creds creds;
		krb5_principal tgtserver;
		krb5_error_code retval;
		krb5_get_init_creds_opt opts;

		pathenv = malloc((strlen(cmddir) + 6) * sizeof(char));
		if (pathenv == NULL) {
			syslog(LOG_ERR, "Not enough memory (env)");
			exit(1);
		}
		sprintf(pathenv, "PATH=%s", cmddir);

		preauth = preauth_list;
#ifdef __osf__
		sprintf(ccname, "FILE:/tmp/afsadm_%d", getpid());
#else
		snprintf(ccname, 255, "FILE:/tmp/afsadm_%d", getpid());
#endif
		if (retval = krb5_cc_resolve(context, ccname, &ccache)) {
			syslog(LOG_ERR, "%s while resolving ccache", error_message(retval));
			exit(1);
		}
#ifdef __osf__
		sprintf(ccname, "KRB5CCNAME=FILE:/tmp/afsadm_%d", getpid());
#else
		snprintf(ccname, 255, "KRB5CCNAME=FILE:/tmp/afsadm_%d", getpid());
#endif

		putenv(ccname);
		if (retval = krb5_cc_initialize(context, ccache, me)) {
			syslog(LOG_ERR, "%s while initialize ccache", error_message(retval));
			exit(1);
		}

		memset((char *)&creds, 0, sizeof(creds));
		creds.client = me;

		if ((retval = krb5_build_principal_ext(context, &tgtserver, krb5_princ_realm(context, me)->length, krb5_princ_realm(context, me)->data, tgtname.length, tgtname.data, krb5_princ_realm(context, me)->length, krb5_princ_realm(context, me)->data, 0))) {
			syslog(LOG_ERR, "%s while building server name", error_message(retval));
			krb5_cc_destroy(context, ccache);
			exit(1);
		}

		creds.server = tgtserver;

		krb5_get_init_creds_opt_init(&opts);
		opts.preauth_list = preauth;

		if (retval = krb5_get_init_creds_keytab(context, &creds, me, keytab, 0, NULL, &opts)) {
			syslog(LOG_ERR, "%s while getting tgt", error_message(retval));
			krb5_cc_destroy(context, ccache);
			exit(1);
		}

		if (retval = krb5_cc_store_cred(context, ccache, &creds)) {
			syslog(LOG_ERR, "%s while saving credentials to ccache", error_message(retval));
			krb5_cc_destroy(context, ccache);
			exit(1);
		}

		if (k_hasafs())
			k_setpag();

		localcmd = malloc(sizeof(char) * (strlen(cmd) + strlen(cmddir) + 2));
		if (localcmd == NULL) {
			syslog(LOG_ERR, "Not enough memory (cmdpath malloc)");
			exit(1);
		}
		sprintf(localcmd, "%s/%s", cmddir, cmd);

		syslog(LOG_INFO, "Principal %s : system(%s)", princ, localcmd);

		/* Set PATH to dircmd !!!! */
		putenv(pathenv);
		//system("/usr/bin/id -a; aklog");

		if (system("aklog") == -1)
			printf("Cannot execute aklog.\n");
		result = system(localcmd);

		syslog(LOG_INFO, "Principal %s : system(%s) returns with %d", princ, localcmd, result);

		free(pathenv);
		free(localcmd);

		if (k_hasafs())
			k_unlog();

		krb5_cc_destroy(context, ccache);
		return 0;
	}
}
