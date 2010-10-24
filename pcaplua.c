

#include <lua.h>
#include <lauxlib.h>

#include <pcap.h>

/*------------ capture device ----------*/

typedef struct l_pcap {
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
} l_pcap;
#define L_PCAP	"pcap obj"
#define check_pcap(L,i)	((l_pcap *)luaL_checkudata (L,i,L_PCAP))


/* capture device methods */
/** compiles and installs a filter
 * @memberof pcap
 * @param filter filter string in tcpdump syntax
 * @return nothing
 */
static int set_filter (lua_State *L) {
	printf ("1,");
	l_pcap *p = check_pcap (L, 1);
	printf ("2,");
	const char *filtstr = luaL_checkstring (L, 2);
	printf ("3,");
	struct bpf_program fp;
	
	printf ("4,");
	if (pcap_compile (p->pcap, &fp, filtstr, 1, 0) == -1) {
		printf ("5,");
		return luaL_error (L, "error compiling \"%s\": %s", filtstr, p->errbuf);
	}
	printf ("6,");
	if (pcap_setfilter (p->pcap, &fp) == -1) {
		printf ("7,");
		return luaL_error (L, "error installing filter \"%s\": %s", filtstr, p->errbuf);
	}
	printf ("8,");
	return 0;
}


static const luaL_Reg pcap_methods[] = {
	{ "set_filter", set_filter },
	
	{ NULL, NULL },
};

/** creates a live capture handle
 * @param dev the device to peek
 * @return pcap userdata object
 */
static int new_live_capture (lua_State *L) {
	const char *dev = luaL_checkstring (L, 1);
	l_pcap *p = lua_newuserdata (L, sizeof (l_pcap));
	p->pcap = pcap_open_live (dev, 0, 0, 0, p->errbuf);
	
	luaL_getmetatable (L, L_PCAP);
	lua_setmetatable (L, -2);
	return 1;
}



static const luaL_Reg module_functs[] = {
	{ "new_live_capture", new_live_capture },
	
	{ NULL, NULL },
};


/*--------- lua module setup ----------*/

static void meta_register (lua_State *L, const luaL_Reg *methods, const char *name) {
	luaL_newmetatable (L, name);
	lua_pushliteral (L, "__index");
	lua_pushvalue (L, -2);
	lua_rawset (L, -3);
	luaL_register (L, NULL, methods);
}


int luaopen_pcaplua (lua_State *L);
int luaopen_pcaplua (lua_State *L) {
	meta_register (L, pcap_methods, L_PCAP);
	luaL_register (L, "pcaplua", module_functs);
	return 1;
}