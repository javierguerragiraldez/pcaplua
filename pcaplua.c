
#include <stdio.h>

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
	l_pcap *p;
	const char *filtstr;
	struct bpf_program fp;

	p = check_pcap (L, 1);
	filtstr = luaL_checkstring (L, 2);

	if (pcap_compile (p->pcap, &fp, filtstr, 1, 0) == -1) {
		return luaL_error (L, "error compiling \"%s\": %s", filtstr, pcap_geterr(p->pcap));
	}
	if (pcap_setfilter (p->pcap, &fp) == -1) {
		return luaL_error (L, "error installing filter \"%s\": %s", filtstr, p->errbuf);
	}
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
	if ((p->pcap = pcap_open_live (dev, 65535, 0, 0, p->errbuf)) == NULL) {
		return luaL_error (L, "error creating capture \"%s\": %s", dev, p->errbuf);
	}

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