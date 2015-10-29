#include <krb5.h>
#include <com_err.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <time.h>

#include "afsadm.h"

/* GNU readline prototypes */
char *readline (char *prompt);
void add_history (char *line);

int	debug;
char	*progname;


#define BUFFSIZE 1024



/*

       CLIENT		SERVER

        ---- connect ------->
	<-- INIT msg ------->	
	--- INIT msg copy -->

	------ auth -------->
	<----- auth ---------

	------- req -------->
	<------ reply len ---
	<------ reply -------
	<------ reply len ---
	<------ reply -------
 	   ...			 
*/

/*********************************************************************
 *
 * Usage
 * 
 *********************************************************************/
void usage(char *progname)
{
	fprintf(stderr, "usage: %s [-d] [-s service] [-c command] [-h hostname]\n", progname); 
}





/*********************************************************************
 *
 * Read commandline, test for exit/quit command
 *
 * read_command() 	0  OK, 1 error, 2 quit/exit
 * command  		contains string from readline
 * 
 *********************************************************************/
int read_command(char **command)
{
	char *line = NULL;
	char *pline = NULL;
	int  len;

	pline = readline("afsadm> ");
	line = pline;

	/* Skip spaces */
	while(isspace(*line))
		line++;

	len = strlen(line);

	/* Remove \n character */
	if(len > 0)
	{
	  if(line[len - 1] == '\n')
		line[len - 1] = '\0';

	  /* Cut spaces */
	  for(len = strlen(line); isspace(line[len - 1]); len = strlen(line))
		line[len - 1] = '\0';
	}

	if(len == 0)
	{
		*command = NULL;
		return(0);	
	}

	if ((*command = (char *)malloc(len + 1)) == NULL)
	{
		fprintf(stderr, "Not enough memory");
		return(1);
	}

	strcpy(*command, line);
	free(pline);
	add_history(*command);

	/* exit or quit -> return 2 */
	if(strcmp(*command, "exit") && strcmp(*command, "quit"))
		return(0);        
	else
		return(2);
}


/**********************************************************************
 *
 * Get encrypted reply from server, decrypt it and close socket
 * 
 * get_reply()		0 OK, 1 error
 * krb5_context		context
 * krb5_auth_context	auth context
 * socket		connection to server
 **********************************************************************/
int client_receive_reply(krb5_context context, 
		krb5_auth_context auth_context,
		int sock )
{
  char		buff[BUFFSIZE];
  short 	netlen;
  int		len, retval, bufflen = BUFFSIZE;
  int		round = 0, encdatalen = 0, datalen = 0;
  krb5_data 	kdata, packet;
  time_t	starttime, endtime;
	
  if(debug) 
	fprintf(stderr, "Receiving encrypted stdout/stderr:\n");

  starttime = time(NULL);


  /* Get reply */
  for( ; ; )
  {
      	int   	reclen;

      	/* Get len of encrypted data */
      	if((len = recv(sock, (char *)&netlen, sizeof(netlen), 0)) < 0)
		 com_err(progname, errno, 
			"while receiving len of encrypted message");

      	/* Is it correct information ? */ 	
      	if(len != sizeof(netlen))
      		break;

      	/* Convert byte order */
      	reclen = (int)ntohs(netlen);

	if(reclen > bufflen)
	{	
		fprintf(stderr, 
			"Cannot receive all encrypted data (small buffer)\n");
		return(1);
	}

	if(debug)
		fprintf(stderr, "\n%d) Expected %d bytes, ", ++round, reclen);
		
	/* Receive encrypted data */
	if((len = recv(sock, buff, reclen, 0)) < 0)
        	com_err(progname, errno, "while receiving encrypted message");

	if(len != reclen)
	{
	  fprintf(stderr, 
	    "Received only %d bytes of encrypted message (expected %d bytes)\n",
	    reclen, len);
	  return(1); 
	}

	if(len > 0)
	{
	  if(debug)
		fprintf(stderr, "received %d/", len);
   
	  packet.data  = NULL;
    	  kdata.data   = buff;
    	  kdata.length = len;

	  /* Decrypt data */
    	  if(retval = krb5_rd_priv(context, auth_context, 
				   &kdata, &packet, NULL))
    	  {
		com_err(progname, retval, "while verifying PRIV message");
		exit(1);
    	  }	
	  
	  if(debug)
		fprintf(stderr, "%d bytes (encr/decr)\n", packet.length);

	  /* Statistics */
	  encdatalen += len;
	  datalen    += packet.length;

	  /* Print decrypted data */
    	  if(write(1, packet.data, packet.length) == -1)
                printf("Failed write to stdout.\n");

	  krb5_xfree(packet.data);
	}
    	
  }    

  endtime = time(NULL);

  printf("\n");
  if(debug)
 	fprintf(stderr, 
	  "End of stdout/stderr [Total: %d/%d bytes (encr/decr) in %ds]\n",
 	  encdatalen, datalen, (int)(endtime - starttime));

    /* All has been received - close socket */
    close(sock);

    /* set NULL auth_context rcache */
    if (retval = krb5_auth_con_setrcache(context, auth_context, NULL))
    {
	com_err(progname, retval, "while setting rcache to NULL");
	return(1);
    }	
}

/********************************************************
 * Connect to an afsadm server		 	
 *
 * onnect_to_server()	returns dns name of the afsadm server
 *
 * host    - host from commandline	  		
 * port    - port from commandline (afsadm service port)
 * retsock - socket connected to server   		
 ********************************************************/

char* connect_to_server(char *host, int port, int *retsock)
{
    struct servent      *sp = NULL;
    struct hostent      *hp = NULL;
    struct sockaddr_in  s_saddr, c_saddr;
    int                 len, sock;
    char                *admhost        = NULL;
    char                *afsadmhostname = AFSADM_HOSTNAME;
    char                *service 	= AFSADM_SERVICE;

    /* Clear out the structure first */
    (void) memset((char *)&s_saddr, 0, sizeof(s_saddr));

    /* Port number from command line */
    if (port != 0)
    {
        s_saddr.sin_family = AF_INET;
        s_saddr.sin_port = htons(port);
    }
    else
    {
        /* Find the port number */
        sp = getservbyname(AFSADM_PORT, "tcp");
        if (!sp)
        {
            fprintf(stderr,
                    "unknown service %s/tcp; check /etc/services or /etc/nsswitch.conf \n",
                    AFSADM_PORT);
            return(NULL);
        }
        /* Copy the port number */
        s_saddr.sin_port = sp->s_port;
        s_saddr.sin_family = AF_INET;
    }

    /* Connect to the afsadm host */

    /* -h option, host(server) from commandline */
    if (host != NULL)
        admhost = host;
    else
        admhost = afsadmhostname;

    if (debug)
        fprintf(stderr, "Trying to resolve name \"%s\"\n", admhost);
    hp = gethostbyname(admhost);

    if (hp)
    {
      if (debug)
          fprintf(stderr, "Name \"%s\" resolved to %s\n", admhost, hp->h_name);
    }
    else
    {
        if (debug)
                fprintf(stderr, "Name \"%s\" not found (unknown host)\n", admhost);
        return(NULL);
    }

     /* set up the address of the foreign socket for connect()  */
     s_saddr.sin_family = hp->h_addrtype;
     (void) memcpy((char *)&s_saddr.sin_addr, (char *)hp->h_addr,
                  sizeof(hp->h_addr));

     /* open a TCP socket */
     sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
     if (sock < 0)
     {
        perror("socket");
        return(NULL);
     }

     if(debug)
        fprintf(stderr, "Trying %s ...\n", hp->h_name);

     /* connect to the server */
     if (connect(sock, (struct sockaddr *)&s_saddr, sizeof(s_saddr)) < 0)
     {
        perror("connect");
        close(sock);

        return(NULL);
     }


    if(debug)
        fprintf(stderr, "Connected to server\n");

    *retsock = sock;
    /* Return socket */
    return(hp->h_name);
}


/***********************************************************************
 *
 * Do mutual authentication
 *
 * client_init_and_authenticate() 	0 OK, 1 error
 *
 * krb5_contex		context
 * akb5_auth_context	auth context
 * krb5_rcache 		replay cache
 * dnsname		afsadm server
 * serv			service name
 * sock			connection to server
 *
 ***********************************************************************/
int client_init_and_authenticate(krb5_context *context, krb5_auth_context *auth_context, 
				 krb5_rcache *rcache, char *dnsname, char *serv, int sock)
{
  
    struct sockaddr_in 	s_saddr, c_saddr;
    int 		len;
    char 		buff[BUFFSIZE];
    char		*admhost        = NULL;
    char		*afsadmhostname = AFSADM_HOSTNAME;
    char 		*service = AFSADM_SERVICE;
    krb5_data 		kdata, packet, cksum_data, rcache_name;
    krb5_error_code 	retval;
    krb5_ccache 	ccdef;
    krb5_principal 	client, server; 
    krb5_error 		*err_ret = NULL; 
    krb5_ap_rep_enc_part *rep_ret = NULL; 
    krb5_address 	ckaddr, skaddr;
   
  /* Initialize krb5 context */
  retval = krb5_init_context(context);
  if (retval) 
  {
	    com_err(progname, retval, "while initializing krb5");
	    return(1);
  }

  (void) signal(SIGPIPE, SIG_IGN);
  if (!valid_cksumtype(CKSUMTYPE_CRC32)) 
  {
	com_err(progname, KRB5_PROG_SUMTYPE_NOSUPP, "while using CRC-32");
	return(1);
  }


  /* Get default kerberos cache */
  if (retval = krb5_cc_default(*context, &ccdef)) 
  {
	com_err(progname, retval, "while getting default ccache");
	return(1);
  }

  /* Get principal from krb cache */
  if (retval = krb5_cc_get_principal(*context, ccdef, &client)) 
  {
        com_err(progname, retval, "while getting client principal name");
        return(1);
  }

   /* Init dialog: receive INIT message from server and send it back */
    if((len = recv(sock, buff, sizeof(buff), 0)) < 0)
    {
        com_err(progname, errno, "while receiving init message");
        return(1);
    }

    if(debug || len == 0)
	fprintf(stderr, "Received init msg: %d bytes\n", len);

    if (len == 0)
	return(1);

    /* Send message back to the server */
    if(send(sock, buff, len, 0) < len)
    {
        com_err(progname, errno, "while sending init reply");
        return(1);
    }



    kdata.data   = dnsname;
    kdata.length = strlen(dnsname);  
    if (retval = krb5_sname_to_principal(*context, dnsname, service,
                                         KRB5_NT_SRV_HST, &server)) 
    {
        com_err(progname, retval, "while creating server name for %s/%s",
                admhost, service);
        return(1);
    }

    cksum_data.data   = NULL;
    cksum_data.length = 0;
    /* Do authetication */
    retval = krb5_sendauth(*context, auth_context, (krb5_pointer) &sock,
                           AFSADM_VERSION, client, server,
                           AP_OPTS_MUTUAL_REQUIRED,
                           &cksum_data,
                           0,           /* no creds, use ccache instead */
                           ccdef, &err_ret, &rep_ret, NULL);

    krb5_free_principal(*context, server);       /* finished using it */

    if(rep_ret)
	krb5_free_ap_rep_enc_part(*context, rep_ret);

    if (retval && retval != KRB5_SENDAUTH_REJECTED) 
    {
        com_err(progname, retval, "while using sendauth");
        return(1);
    }

    if (retval == KRB5_SENDAUTH_REJECTED) 
    {
        /* got an error */
        printf("sendauth rejected, error reply is:\n\t\"%*s\"\n",
               err_ret->text.length, err_ret->text.data);
	return(1);
    }

    if(debug)
	fprintf(stderr, "Successfuly authenticated\n");

    /* Get my address */
    memset((char *) &c_saddr, 0, sizeof(c_saddr));
    len = sizeof(c_saddr);
    if (getsockname(sock, (struct sockaddr *)&c_saddr, &len) < 0) 
    {
        com_err(progname, errno, "while getting socket name");
        return(1);
    }

    /* Get server address */
    if (getpeername(sock, (struct sockaddr *)&s_saddr, &len) < 0)
    {
        com_err(progname, errno, "while getting peer name");
        return(1);
 	
    }

    ckaddr.addrtype = ADDRTYPE_IPPORT;
    ckaddr.length   = sizeof(c_saddr.sin_port);
    ckaddr.contents = (krb5_octet *)&c_saddr.sin_port;

    skaddr.addrtype = ADDRTYPE_IPPORT;
    skaddr.length   = sizeof(s_saddr.sin_port);
    skaddr.contents = (krb5_octet *)&s_saddr.sin_port;

    /* Set ports in auth_context */
    if ((retval    = krb5_auth_con_setports(*context, *auth_context,
                                         &ckaddr, &skaddr))) 
    {
        com_err(progname, retval, "while setting ports\n");
        return(1);
    }

    ckaddr.addrtype = ADDRTYPE_INET;
    ckaddr.length   = sizeof(c_saddr.sin_addr);
    ckaddr.contents = (krb5_octet *)&c_saddr.sin_addr;

    skaddr.addrtype = ADDRTYPE_INET;
    skaddr.length   = sizeof(s_saddr.sin_addr);
    skaddr.contents = (krb5_octet *)&s_saddr.sin_addr;

    /* Set addresses in auth_context */
    if ((retval    = krb5_auth_con_setaddrs(*context, *auth_context,
                                         &ckaddr, &skaddr))) 
    {
        com_err(progname, retval, "while setting  addr\n");
        return(1);
    }

    rcache_name.data   = "afsadmclnt";
    rcache_name.length = strlen(rcache_name.data);

    if ((retval = krb5_get_server_rcache(*context, &rcache_name, rcache))) 
    {
        com_err(progname, retval, "while getting rcache");
        return(1);
    }

    /* Set auth_context rcache */
    if (retval = krb5_auth_con_setrcache(*context, *auth_context, *rcache))
    {
	com_err(progname, retval, "while setting rcache");
	return(1);
    }	

    return(0);
}


/***********************************************************************
 *
 * Send encrypted request to server
 *
 * client_send_request() -1 error
 *
 *
 ***********************************************************************/
client_send_request(krb5_context context, krb5_auth_context auth_context, int sock, char *request)
{

    krb5_data 		data, kdata;
    krb5_error_code 	retval;
    krb5_error 		*err_ret = NULL; 
    int 		len;
 
    /* Plain request */
    data.data   = request;
    data.length = strlen(request) + 1;

    /* Make the encrypted message */
    if ((retval = krb5_mk_priv(context, auth_context, &data,
                               &kdata, NULL))) 
    {
        com_err(progname, retval, "while making KRB_PRIV message");
        return(-1);
    }

    /* Send it to the server */
    if ((len = send(sock, (char *)kdata.data, kdata.length, 0)) < 0)
    {
        com_err(progname, errno, "while sending PRIV message");
	return(-1);
    }

    if(debug)
    	fprintf(stderr, "Sent encrypted message: %d bytes\n", len);

    return(len);
}


/*****************************************************************
 *
 * Connext to server, do authentication, send request and get reply
 *
 *****************************************************************/
int do_request(char *host, int port, char *serv, char *request)
{
  int             	socket;
  int			retval	     = 0;
  krb5_context		context      = 0;
  krb5_auth_context 	auth_context = 0;
  krb5_rcache 		rcache;
  char            	*dnsname     = NULL;

  if((dnsname = connect_to_server(host, port, &socket)) == NULL)
                return(1);
  if (client_init_and_authenticate(&context, &auth_context, &rcache, dnsname, serv, socket))
                return(1);
  if (client_send_request(context, auth_context, socket, request) < 0)
                return(1);
  else if (client_receive_reply(context, auth_context, socket) < 0)
                return(1);

  krb5_rc_destroy(context, rcache);
  krb5_auth_con_free(context, auth_context);
  krb5_free_context(context); 
  
  return(0);
}

/*********************************************************************
 *
 * Main()
 * 
 *********************************************************************/

int main(int argc, char **argv)
{
    char 	*host = NULL, 
		*serv = NULL;     
    char 	*command = NULL;
    int  	port = 0, ch;
    extern int 	opterr, optind;
    extern char *optarg;


    debug 	= 0;
    progname 	= *argv;

    /*
     * Parse command line arguments
     *  
     */
    opterr = 0;
    while ((ch = getopt(argc, argv, "ds:c:h:")) != EOF)
    switch (ch) {
    case 'c':
	command = optarg;
	break;
    case 's':
	serv = optarg;
	break;
    case 'd':
	debug++;
	break;
    case 'h':
	host = optarg;
	break;
    case '?':
    default:
	usage(progname);
	exit(1);
	break;
    }

    argc -= optind;
    argv += optind;

    if(command)
    {
	if (do_request(host, port, serv, command))
	  return(1);
    }
    else
      for ( ; ; )
      {
      	if (read_command(&command))
		break;
	if (command != NULL)
	{
		if(do_request(host, port, serv, command))
			return(1);
		free(command);
	}
        	
      }
 
    return(0);
}

