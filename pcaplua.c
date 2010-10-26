
#include <stdio.h>

#include <lua.h>
#include <lauxlib.h>

#include <pcap.h>
#include "headers.h"


#define set_field(L,k,v,type)	do{							\
								lua_pushliteral(L,k);		\
								lua_push ## type (L,(v));	\
								lua_rawset(L,-3);			\
							} while(0)
#define set_field_lstr(L,k,v,l)	do{							\
								lua_pushliteral(L,k);		\
								lua_pushlstring (L,(const char*)(v),(l));	\
								lua_rawset(L,-3);			\
							} while(0)

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

/** injects a packet in the stream
 * @memberof pcap
 * @param data packet's data to send
 * @return (true,unsent data) on success; (nil,error) on failure
 */
static int inject (lua_State *L) {
	l_pcap *p = check_pcap (L,1);
	size_t dz;
	const char *d = luaL_checklstring (L,2,&dz);

	int ret = pcap_inject (p->pcap, d, dz);
	if (ret <0) {
		lua_pushnil (L);
		lua_pushstring (L, p->errbuf);
		return 2;
	}
	lua_pushboolean (L,1);
	lua_pushlstring (L, d+ret, dz-ret);
	return 2;
}


static const luaL_Reg pcap_methods[] = {
	{ "set_filter", set_filter },
	{ "next", next },
	{ "inject", inject },

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

static void use_or_create_table (lua_State *L, int na, int nh) {
	if (!lua_istable (L,-1)) {
		lua_pop (L, 1);
		lua_createtable (L, na, nh);
	}
}
/** decodes ethernet header
 * @param packet
 * @param optional table to fill with header data
 * @return table with decoded header data
 */
static int decode_ethernet (lua_State *L) {
	size_t sz=0;
	const char *pd = luaL_checklstring (L, 1, &sz);
	use_or_create_table (L, 0, 4);

	const struct sniff_ethernet *ethernet = (struct sniff_ethernet*)(pd);

	set_field_lstr (L, "dst", ethernet->ether_dhost, ETHER_ADDR_LEN);
	set_field_lstr (L, "src", ethernet->ether_shost, ETHER_ADDR_LEN);
	set_field (L, "type", ethernet->ether_type, integer);
	set_field_lstr (L, "content", pd+SIZE_ETHERNET, sz-SIZE_ETHERNET);
	return 1;
}



static const luaL_Reg module_functs[] = {
	{ "new_live_capture", new_live_capture },
	{ "decode_ethernet", decode_ethernet },

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
