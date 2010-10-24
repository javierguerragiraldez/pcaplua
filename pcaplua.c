
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

	if (pcap_compile (p->pcap, &fp, filtstr, 1, PCAP_NETMASK_UNKNOWN) == -1) {
		return luaL_error (L, "error compiling \"%s\": %s", filtstr, pcap_geterr(p->pcap));
	}
	if (pcap_setfilter (p->pcap, &fp) == -1) {
		return luaL_error (L, "error installing filter \"%s\": %s", filtstr, p->errbuf);
	}
	return 0;
}

/** gets one packet
 * @memberof pcap
 * @return packet data, timestamp, offwire length
 */
static int next (lua_State *L) {
	l_pcap *p = check_pcap(L,1);
	struct pcap_pkthdr ph;
	const u_char *d = pcap_next (p->pcap, &ph);
	if (!d) {
		return 0;
	}
	lua_pushlstring (L, (char *)d, ph.caplen);
	lua_pushnumber (L, ph.ts.tv_sec + ph.ts.tv_usec/1000000.0);
	lua_pushinteger (L, ph.len);
	return 3;
}


static const luaL_Reg pcap_methods[] = {
	{ "set_filter", set_filter },
	{ "next", next },

	{ NULL, NULL },
};

/** creates a live capture handle
 * @param dev the device to peek
 * @param promisc promic mode
 * @return pcap userdata object, device name used
 */
static int new_live_capture (lua_State *L) {
	const char *dev = luaL_optstring (L, 1, NULL);
	l_pcap *p = lua_newuserdata (L, sizeof (l_pcap));
	if (!dev) {
		dev = pcap_lookupdev (p->errbuf);
	}
	if (!dev) {
		return luaL_error (L, "no device: %s", p->errbuf);
	}
	//TODO: better capture size and to_ms
	if ((p->pcap = pcap_open_live (dev, 65535, lua_toboolean(L,2), 0, p->errbuf)) == NULL) {
		return luaL_error (L, "error creating capture \"%s\": %s", dev, p->errbuf);
	}

	luaL_getmetatable (L, L_PCAP);
	lua_setmetatable (L, -2);
	lua_pushstring (L, dev);
	return 2;
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
