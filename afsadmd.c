#include <krb5.h>
#include <com_err.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>

#include "afsadm.h"


/**************************************************************************/

extern krb5_deltat 	krb5_clockskew;
int    			debug;


#define 	BUFFSIZE	2000
#define		PIPEBUFF	501
#define	   	RC_PIECE_MAXLEN	50

int do_krb5_comm(krb5_context context, krb5_keytab keytab, 
		krb5_principal server, char *cmddir)
{
    struct sockaddr_in	c_saddr, s_saddr;
    int 		namelen;
    int			sock = 0;
    int			len;
    char		buff[BUFFSIZE];
    char		*cname = NULL;
    krb5_error_code	retval;
    krb5_data		kdata, message;
    krb5_auth_context 	auth_context = NULL;
    krb5_ticket		*ticket;
    krb5_address 	ckaddr, skaddr;
    krb5_rcache 	rcache;
    krb5_data   	rcache_name;
    long		srand, rrand;
    int			fd[2];
    char 		rcname_piece[RC_PIECE_MAXLEN];

    namelen = sizeof(c_saddr);
    if (getpeername(sock, (struct sockaddr *)&c_saddr, &namelen) < 0) 
    {
	    syslog(LOG_ERR, "getpeername: %m");
	    return(1);
    }

    namelen = sizeof(s_saddr);
    if (getsockname(sock, (struct sockaddr *)&s_saddr, &namelen) < 0)
    {
	syslog(LOG_ERR, "getsockname: %m");
	return(1);
    } 

    /* INIT MSG = random number */
    srand = random();
 
    /* Send it */
    if (send(sock, &srand, sizeof(srand), 0) < 0)
    {
         syslog(LOG_ERR, "%m while sending init message");
	 return(1);
    }
    if(recv(sock, &rrand, sizeof(rrand), 0) < 0)
    {
        syslog(LOG_ERR, "%m while receiving init reply");
	return(1);
    }

    /* Reply should contain the same message (number) */
    if(srand != rrand)
    {
	syslog(LOG_ERR, "Bad init reply");
	return(1);
    }
    
    /* Do authentication */
    if (retval = krb5_recvauth(context, &auth_context, (krb5_pointer)&sock,
                               AFSADM_VERSION, server, 
                               0,       /* no flags */
                               keytab,  /* default keytab is NULL */
                               &ticket)) 
    {
        syslog(LOG_ERR, "recvauth failed: %s", error_message(retval));
        exit(1);
    }

    /* Get client name */
    if (retval = krb5_unparse_name(context, ticket->enc_part2->client, &cname))
    {
	syslog(LOG_ERR, "unparse failed: %s", error_message(retval));
        return(1);
    }

    if(ticket)
	krb5_free_ticket(context, ticket);

    if(debug)
	syslog(LOG_DEBUG, "Principal %s", cname);

    /*******************************************************************/

    ckaddr.addrtype = ADDRTYPE_IPPORT;
    ckaddr.length   = sizeof(c_saddr.sin_port);
    ckaddr.contents = (krb5_octet *)&c_saddr.sin_port;

    skaddr.addrtype = ADDRTYPE_IPPORT;
    skaddr.length   = sizeof(s_saddr.sin_port);
    skaddr.contents = (krb5_octet *)&s_saddr.sin_port;
    if ((retval = krb5_auth_con_setports(context, auth_context,
                                         &skaddr, &ckaddr))) {
        syslog(LOG_ERR, "%s while setting ports",
			error_message(retval));
        return(1);
    }


    /* Set foreign_addr for rd_priv() */
    ckaddr.addrtype = ADDRTYPE_INET;
    ckaddr.length   = sizeof(c_saddr.sin_addr);
    ckaddr.contents = (krb5_octet *)&c_saddr.sin_addr;

    /* Set local_addr  */
    skaddr.addrtype = ADDRTYPE_INET;
    skaddr.length   = sizeof(s_saddr.sin_addr);
    skaddr.contents = (krb5_octet *)&s_saddr.sin_addr;
    
    if ((retval = krb5_auth_con_setaddrs(context, auth_context,
                                         &skaddr, &ckaddr))) {
        syslog(LOG_ERR, "%s while setting addrs", 
			error_message(retval));
        return(1);
    }

    /* Receive a request */
    if ((len = recv(sock, (char *)buff, sizeof(buff), 0)) < 0)
    {
        syslog(LOG_ERR, "%m while receiving datagram");
        return(1);
    }

    kdata.length = len;
    kdata.data   = buff;

    if(debug)
	syslog(LOG_DEBUG, "Received %d bytes", len);

   /* Decrypt it */ 
   if ((retval = krb5_rd_priv(context, auth_context, &kdata,
                               &message, NULL))) 
    {
        syslog(LOG_ERR, "%s while verifying PRIV message", 
			error_message(retval));
        return(1);
    }

    if(message.length > 0)
    {	
		
#ifdef __osf__
      sprintf(rcname_piece, "afsadmd_%d",  getpid());
#else
      snprintf(rcname_piece, RC_PIECE_MAXLEN, "afsadmd_%d", getpid());
#endif
      rcache_name.data = rcname_piece;
      rcache_name.length = strlen(rcache_name.data);
     

      if ((retval = krb5_get_server_rcache(context, &rcache_name, &rcache))) {
        syslog(LOG_ERR, "%s while getting server rcache",
		error_message(retval));
        return(1);
      }

      /* set auth_context rcache */
      if (retval = krb5_auth_con_setrcache(context, auth_context, rcache))
      {
	syslog(LOG_ERR, "%s while setting rcache",
		error_message(retval));
	return(1);
      }	
   	
      /*********************************************************************
       * Call the desired command, read stdout/stderr, send it 
       *********************************************************************/	

     /* create fork */
     if (pipe(fd) == -1)
          printf("Failed create fork with pipe().\n");

     if(fork() == 0)
     {
	  close(fd[0]);
	  close(1);
	  close(2);
	  dup2(fd[1], 1);
	  dup2(fd[1], 2);

	  /* Call required command */
	  do_command(context, keytab, server, cname, message.data, cmddir );
          krb5_xfree(message.data);  
	  exit(0);  	
      }
      else /* Read stdout/stderr from pipe, store it to the buffer, 
              encrypt it a send to the client */
      { 
	krb5_data 	message, kdata;
	char		buff[PIPEBUFF];
	int		n   	= 0,
			len     = 0,
	 		sent 	= 0, 
			counter = 0,
			end	= 0;
	short		netlen;
	time_t		starttime, oldtime, newtime;
	FILE		*pipedes;
		
	close(fd[1]);
	pipedes = fdopen(fd[0], "r");

	starttime = oldtime = time(NULL);

	for(n = 0; end == 0; )
	{
	  /* Read line from pipe */
	  if(fgets(buff + n, PIPEBUFF - n, pipedes) == NULL)
		end++;
	  else
	  	n = strlen(buff);

	  /* Get time */
	  newtime = time(NULL);

	  /* Send buffer when
	   *	a) buffer is full 
	   *    b) buffer contains data and
	   *    	1) end-of-file encountered (end flag) 
	   *		2) buffer sent before 1s
	   */
	  if(	(n == PIPEBUFF) || 
		(((newtime > oldtime) || end ) && (n != 0)))
	  {		

		/* Prepare data for sending */
		message.data   = buff;
		message.length = n;
		kdata.data     = NULL;

      		/* Make the encrypted message */
      		if ((retval = krb5_mk_priv(context, auth_context, &message,
                               &kdata, NULL))) 
		{
        	  syslog(LOG_ERR, "%s while making KRB_PRIV message",
		  	error_message(retval));
        	  return(1);
		}

		/* Convert byte order */
		netlen = htons((short)kdata.length);
		
		/* Send len of encrypted data */
		if((len = send(sock, (char *)&netlen, sizeof(netlen), 0)) 
				!= sizeof(netlen))
		{
		  krb5_xfree(kdata.data);
		  syslog(LOG_ERR, "%m while sending len of PRIV message");
		  return(1);
		}

      		/* Send it */
      		if ((len = send(sock, (char *)kdata.data, kdata.length, 0)) 
							!= kdata.length)
		{
          	  syslog(LOG_ERR, "%m while sending PRIV message");
		  krb5_xfree(kdata.data);
		  return(1); 
		}

		/* Statistics */
		sent += len;
		counter++;

		/* Timestanmp */
	    	oldtime = newtime;
		n       = 0;
		
		krb5_xfree(kdata.data);
	    }
	} /* for() */

	newtime = time(NULL);

      	if(debug)
	  syslog(LOG_DEBUG, "Sent %d bytes in %ds [%d fragment(s)]", 
			sent, (int)(newtime - starttime),  counter);	
	
      }   /* fork */ 

    }

      krb5_rc_destroy(context, rcache);
/*      krb5_rc_close(context, rcache);   */

      /* set auth_context rcache */
      if (retval = krb5_auth_con_setrcache(context, auth_context, rcache))
      {
	syslog(LOG_ERR, "%s while setting rcache to NULL", 
			error_message(retval));
	return(1);
      }	
    
    free(cname);   
    krb5_auth_con_free(context, auth_context);
    return(0);
}



void usage(char *name)
{
	fprintf(stderr, "usage: %s [-c confdir] [-s service] [-S keytab] [-d]\n", name);
}	




int main(int argc, char **argv)
{
    krb5_context 	context;
    krb5_error_code 	retval;
    krb5_principal 	server;
    krb5_keytab 	keytab = NULL;	/* Allow specification on command line*/
    extern int 		opterr, optind;
    extern char 	*optarg;
    int 		ch;
    char 		*progname,
		 	*cfgfile,
			*cmddir,
			*cfgname = AFSADMCONFIGNAME, 
			*cfgdir = AFSADMDIR,
			*service = AFSADM_SERVICE;

    /*********************************************************************/
    debug 	= 0;
    progname 	= *argv;

    /* open a log connection */
    openlog("afsadmd", LOG_PID, LOG_DAEMON);


    retval = krb5_init_context(&context);
    if (retval) 
    {
	    syslog(LOG_ERR, "while initializing krb5: %s", 
				error_message(retval));
	    exit(1);
    }


    /*
     * Parse command line arguments
     *  
     */
    opterr = 0;
    while ((ch = getopt(argc, argv, "dS:s:c:")) != EOF)
    switch (ch) {
    case 'c':
	cfgdir = optarg;
	break;
    case 's':
	service = optarg;
	break;
    case 'S':
	if (retval = krb5_kt_resolve(context, optarg, &keytab)) {
	    syslog(LOG_ERR,
		    "while resolving keytab file %s: %s", 
		     optarg, error_message(retval));
	    exit(2);
	}
	break;
    case 'd':
	debug++;
	break;
    case '?':
    default:
	usage(progname);
	exit(1);
	break;
    }

    argc -= optind;
    argv += optind;

 
    if (retval = krb5_sname_to_principal(context, NULL, service, 
					 KRB5_NT_SRV_HST, &server)) 
    {
	syslog(LOG_ERR, "while generating service name (%s): %s",
	       service, error_message(retval));
	exit(1);
    }


    /******************************************************************/
    /*
     * Config file
     */    
    
    if((cfgfile = (char *)malloc(sizeof(char) * 
		  (strlen(cfgdir) + strlen(cfgname) + 2))) == NULL)
    {
	syslog(LOG_ERR, 
		"%m: while allocating buffer for configuration filename");
	exit(1);
    }
    sprintf(cfgfile, "%s/%s", cfgdir, cfgname);	

    /* cmddir = cfgdir/bin */
    if((cmddir = (char *)malloc(sizeof(char) * 
		  (strlen(cfgdir) + 4))) == NULL)
    {
	syslog(LOG_ERR, 
		"%m: while allocating buffer for configuration directory");
	exit(1);
    }
    sprintf(cmddir, "%s/bin", cfgdir);	
	
    if(debug)
	syslog(LOG_DEBUG, "Parsing configfile %s", cfgfile);

    if(parse_config_file(cfgfile))
		exit(1);
   
    /*********************************************************************/

    do_krb5_comm(context, keytab, server, cmddir);    

    free(cfgfile);
    free(cmddir);
    krb5_free_context(context);
    exit(0);
}
