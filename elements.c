#include <string.h>
#include <unistd.h>

#include "elements.h"

// Element handlers: Depth 0.
static void	el_record(const char **attr, const char *body);

// Element handlers: Depth 1.
static void	el_arbitrary(const char **attr, const char *body);
static void	el_argument(const char **attr, const char *body);
static void	el_attribute(const char **attr, const char *body);
static void	el_exec_args(const char **attr, const char *body);
static void	el_exec_env(const char **attr, const char *body);
static void	el_exit(const char **attr, const char *body);
static void	el_file(const char **attr, const char *body);
static void	el_group(const char **attr, const char *body);
static void	el_ip(const char **attr, const char *body);
static void	el_ip_address(const char **attr, const char *body);
static void	el_ip_port(const char **attr, const char *body);
static void	el_ipc(const char **attr, const char *body);
static void	el_ipc_perm(const char **attr, const char *body);
static void	el_opaque(const char **attr, const char *body);
static void	el_path(const char **attr, const char *body);
static void	el_process(const char **attr, const char *body);
static void	el_return(const char **attr, const char *body);
static void	el_sequence(const char **attr, const char *body);
static void	el_socket(const char **attr, const char *body);
static void	el_socket_inet(const char **attr, const char *body);
static void	el_socket_inet6(const char **attr, const char *body);
static void	el_subject(const char **attr, const char *body);
static void	el_text(const char **attr, const char *body);
static void	el_zone(const char **attr, const char *body);

// Element handlers: Depth 2.
static void	el_arg(const char **attr, const char *body);
static void	el_env(const char **attr, const char *body);
static void	el_grp(const char **attr, const char *body);

static struct element_pair {
	char	*name;
	void	 (*func)(const char **attr, const char *body);
} el_handlers[] = {
	// Element: Depth 0.
	{"record",		el_record},

	// Element: Depth 1.
	{"arbitrary",		el_arbitrary},
	{"argument",		el_argument},
	{"attribute",		el_attribute},
	{"exec_args",		el_exec_args},
	{"exec_env",		el_exec_env},
	{"exit",		el_exit},
	{"file",		el_file},
	{"group",		el_group},
	{"ip",			el_ip},
	{"ip_address",		el_ip_address},
	{"ip_port",		el_ip_port},
	{"IPC",			el_ipc},
	{"IPC_perm",		el_ipc_perm},
	{"opaque",		el_opaque},
	{"path",		el_path},
	{"process",		el_process},
	{"return",		el_return},
	{"sequence",		el_sequence},
	{"socket",		el_socket},
	{"socket-inet",		el_socket_inet},
	{"socket-inet6",	el_socket_inet6},
	{"subject",		el_subject},
	{"text",		el_text},
	{"zone",		el_zone},

	// Element: Depth 2.
	{"arg",			el_arg},
	{"env",			el_env},
	{"grp",			el_grp},

	// Terminator.
	{NULL,			NULL}
};

/*
 * Dispatch the handling of an element to the appropriate handler.
 */
void
handleElement(const char *el, const char **attr, const char *body)
{
	int i;

	for (i = 0; el_handlers[i].name != NULL; i++) {
		/* Check if tag matches handler. */
		if (strcmp(el, el_handlers[i].name) != 0)
			continue;

		/* Check if tag is unimplemented. */
		if (el_handlers[i].func == NULL)
			break;

		/* Call element handler. */
		el_handlers[i].func(attr, body);
	}
}

/*
 * [arbitrary]
 *
 * Attribute
 * ---------
 * count
 * print
 * type
 *
 * Tokens
 * ------
 * AUT_DATA
 *
 * The body of this element contains arbitrary data in the format defined by the
 * print and type attributes.
 */
static void
el_arbitrary(const char **attr, const char *body)
{
}

/*
 * [arg]
 */
static void
el_arg(const char **attr, const char *body)
{
}

/*
 * [argument]
 *
 * Attribute
 * ---------
 * arg-num
 * desc
 * value
 *
 * Tokens
 * ------
 * AUT_ARG32
 * AUT_ARG64
 */
static void
el_argument(const char **attr, const char *body)
{
}

/*
 * [attribute]
 *
 * Attribute
 * ---------
 * device
 * fsid
 * gid
 * mode
 * nodeid
 * uid
 *
 * Tokens
 * ------
 * AUT_ATTR32
 * AUT_ATTR64
 */
static void
el_attribute(const char **attr, const char *body)
{
}

/*
 * [env]
 */
static void
el_env(const char **attr, const char *body)
{
}

/*
 * [exec_args]
 *
 * Tokens
 * ------
 * AUT_EXEC_ARGS
 *
 * The body of this element contains arg elements.
 */
static void
el_exec_args(const char **attr, const char *body)
{
}

/*
 * [exec_env]
 *
 * Tokens
 * ------
 * AUT_EXEC_ENV
 *
 * The body of this element contains env elements.
 */
static void
el_exec_env(const char **attr, const char *body)
{
}

/*
 * [exit]
 *
 * Attribute
 * ---------
 * errval
 * retval
 *
 * Tokens
 * ------
 * AUT_EXIT
 */
static void
el_exit(const char **attr, const char *body)
{
}

/*
 * [file]
 *
 * Attribute
 * ---------
 * msec
 * time
 *
 * Tokens
 * ------
 * AUT_OTHER_FILE32
 *
 * The body of this element contains a file name.
 */
static void
el_file(const char **attr, const char *body)
{
}

/*
 * [group]
 *
 * Tokens
 * ------
 * AUT_NEWGROUPS
 *
 * The body of this element contains grp elements.
 */
static void
el_group(const char **attr, const char *body)
{
}

/*
 * [grp]
 */
static void
el_grp(const char **attr, const char *body)
{
}

/*
 * [ip]
 *
 * Attribute
 * ---------
 * cksum
 * dest_addr
 * id
 * len
 * offset
 * protocol
 * service_type
 * src_addr
 * time_to_live
 * version
 *
 * Tokens
 * ------
 * AUT_IP
 */
static void
el_ip(const char **attr, const char *body)
{
}

/*
 * [ip_address]
 *
 * Tokens
 * ------
 * AUT_IN_ADDR
 * AUT_IN_ADDR_EX
 *
 * The body of this element contains an IP address.
 */
static void
el_ip_address(const char **attr, const char *body)
{
}

/*
 * [ip_port]
 *
 * Tokens
 * ------
 * AUT_IPORT
 */
static void
el_ip_port(const char **attr, const char *body)
{
}

/*
 * [IPC]
 *
 * Attribute
 * ---------
 * ipc-id
 * ipc-type
 *
 * Tokens
 * ------
 * AUT_IPC
 */
static void
el_ipc(const char **attr, const char *body)
{
}

/*
 * [IPC_perm]
 *
 * Attribute
 * ---------
 * creator-gid
 * creator-uid
 * gid
 * key
 * mode
 * seq
 * uid
 *
 * Tokens
 * ------
 * AUT_IPC_PERM
 */
static void
el_ipc_perm(const char **attr, const char *body)
{
}

/*
 * [opaque]
 *
 * Tokens
 * ------
 * AUT_OPAQUE
 *
 * The body of this element contains hex data.
 */
static void
el_opaque(const char **attr, const char *body)
{
}

/*
 * [path]
 *
 * Tokens
 * ------
 * AUT_PATH
 *
 * The body of this element contains a path.
 */
static void
el_path(const char **attr, const char *body)
{
}

/*
 * [process]
 *
 * Attribute
 * ---------
 * audit-uid
 * gid
 * pid
 * rgid
 * ruid
 * sid
 * tid
 * uid
 *
 * Tokens
 * ------
 * AUT_PROCESS32
 * AUT_PROCESS32_EX
 * AUT_PROCESS64
 * AUT_PROCESS64_EX
 */
static void
el_process(const char **attr, const char *body)
{
}

/*
 * [record]
 *
 * Attribute
 * ---------
 * event
 * host (only in *_EX)
 * modifier
 * msec
 * time
 * version
 *
 * Tokens
 * ------
 * AUT_HEADER32
 * AUT_HEADER32_EX
 * AUT_HEADER64
 * AUT_HEADER64_EX
 * AUT_TRAILER
 */
static void
el_record(const char **attr, const char *body)
{
}

/*
 * [return]
 *
 * Attribute
 * ---------
 * errval
 * retval
 *
 * Tokens
 * ------
 * AUT_RETURN32
 * AUT_RETURN64
 */
static void
el_return(const char **attr, const char *body)
{
}

/*
 * [sequence]
 *
 * Attribute
 * ---------
 * seq-num
 *
 * Tokens
 * ------
 * AUT_SEQ
 */
static void
el_sequence(const char **attr, const char *body)
{
}

/*
 * [socket]
 *
 * Attribute
 * ---------
 * faddr
 * fport
 * laddr
 * lport
 * sock_dom (only *_EX)
 * sock_type
 *
 * Tokens
 * ------
 * AUT_SOCKET
 * AUT_SOCKET_EX
 */
static void
el_socket(const char **attr, const char *body)
{
}

/*
 * [socket-inet]
 *
 * Attribute
 * ---------
 * addr
 * port
 * type
 *
 * Tokens
 * ------
 * AUT_SOCKINET32
 * AUT_SOCKUNIX
 */
static void
el_socket_inet(const char **attr, const char *body)
{
}

/*
 * [socket-inet6]
 *
 * Attribute
 * ---------
 * addr
 * port
 * type
 *
 * Tokens
 * ------
 * AUT_SOCKINET128
 */
static void
el_socket_inet6(const char **attr, const char *body)
{
}

/*
 * [subject]
 *
 * Attribute
 * ---------
 * audit-uid
 * gid
 * pid
 * rgid
 * ruid
 * sid
 * tid
 * uid
 *
 * Tokens
 * ------
 * AUT_SUBJECT32
 * AUT_SUBJECT64
 * AUT_SUBJECT32_EX
 * AUT_SUBJECT64_EX
 */
static void
el_subject(const char **attr, const char *body)
{
}

/*
 * [text]
 *
 * Tokens
 * ------
 * AUT_TEXT
 *
 * The body of this element contains arbitrary text.
 */
static void
el_text(const char **attr, const char *body)
{
}

/*
 * [zone]
 *
 * Attribute
 * ---------
 * name
 *
 * Tokens
 * ------
 * AUT_ZONENAME
 */
static void
el_zone(const char **attr, const char *body)
{
}
