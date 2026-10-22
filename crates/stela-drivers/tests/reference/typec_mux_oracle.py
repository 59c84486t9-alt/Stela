#!/usr/bin/env python3
"""Compile unchanged PI3/TUSB/NB7/PS8830 programming routines from pinned Linux.

Scalar metadata, register storage and regulator/GPIO primitives are stubs. This
compares controller effects, not Linux discovery, physical signals or GPU state.
Usage: python3 typec_mux_oracle.py SOURCE_DIRECTORY OUTPUT_DIRECTORY
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
source, out = map(Path, sys.argv[1:])
pins = {
    "pi3usb30532.c": "f38998f2252c3e7fb03de546a5bd0af653a0dfe6a133df1c018193010f570ce1",
    "tusb1046.c": "bf1085fe299b93710fa2d8becad6bce17eb1dbe01e7e479cf3092eb8c47011c0",
    "nb7vpq904m.c": "e05c72fcacfdf0c0873c14d3602ba74e7e32467ea75f4a3ed9eb3f0cf5be6d6a",
    "ps883x.c": "701b018715378aa95bea81b77f04d34dae7c0484593bfba54c2a92cd62f0cb19",
    "typec_altmode.h": "d934b5d661883983fd6bb662e059db007fb06d526bb31d05d45e6cf4a0a706be",
    "typec_dp.h": "601bc7daf26aee18d4efce18e18af659c9b5937ca59b16f4026e7cde04ba2c50",
    "typec_tbt.h": "4e7613286cc3e318736a794c30422fe236acef16c805f1665c4f6570ed7f109d",
    "pd.h": "c844b3db3f0e4f3cf760d68ba3ff96145d73988c8d030aad8c29b2c1e9a88b50",
}
for name, digest in pins.items():
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest, name
out.mkdir(parents=True, exist_ok=True)


def function(text, name):
    match = re.search(r"^static[^;{}]*?\b" + name + r"\([^;{}]*?\)\n\{", text, re.M)
    assert match, name
    at, depth = match.end(), 1
    while depth:
        depth += (text[at] == "{") - (text[at] == "}")
        at += 1
    return text[match.start():at]


def defines(text, prefix=None, names=None):
    result = []
    for match in re.finditer(r"^#define\s+([A-Za-z0-9_]+)[^\n]*", text, re.M):
        if prefix and match[1].startswith(prefix) or names and match[1] in names:
            result.append(match.group())
    return "\n".join(result) + "\n"


alt = (source / "typec_altmode.h").read_text()
dp = (source / "typec_dp.h").read_text()
enums = "\n".join(enum for enum in re.findall(r"enum \{.*?\n\};", alt + dp, re.S) if "TYPEC_STATE_SAFE" in enum or "TYPEC_MODE_USB2" in enum or "TYPEC_DP_STATE_A" in enum)
common = r'''// SPDX-License-Identifier: GPL-2.0-only
// Retains donor copyrights recorded in the checked-in third-party notice.
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;typedef uint32_t u32;
#define BIT(n) (1U<<(n))
#define GENMASK(h,l) (((~0U)>>(31-(h)))&((~0U)<<(l)))
#define FIELD_PREP(m,v) (((v)<<__builtin_ctz(m))&(m))
#define FIELD_GET(m,v) (((v)&(m))>>__builtin_ctz(m))
#define EINVAL 22
#define EOPNOTSUPP 95
#define mutex_lock(p) ((void)(p))
#define mutex_unlock(p) ((void)(p))
#define dev_err(dev,...) ((void)(dev))
#define dev_dbg(dev,...) ((void)(dev))
#define fallthrough __attribute__((fallthrough))
enum typec_orientation {TYPEC_ORIENTATION_NONE,TYPEC_ORIENTATION_NORMAL,TYPEC_ORIENTATION_REVERSE};
struct device {int unused;};struct i2c_client {struct device dev;};
struct typec_switch_dev {void *data;};struct typec_mux_dev {void *data;};
#define typec_switch_get_drvdata(s) ((s)->data)
#define typec_mux_get_drvdata(s) ((s)->data)
struct typec_altmode {unsigned int svid;};
struct typec_mux_state {unsigned long mode;struct typec_altmode *alt;void *data;};
struct typec_retimer_state {unsigned long mode;struct typec_altmode *alt;void *data;};
struct typec_thunderbolt_data {u32 cable_mode,enter_vdo,device_mode;};
struct enter_usb_data {u32 eudo;};
static unsigned char registers[256];static unsigned int writes;
static __attribute__((unused)) int i2c_smbus_read_byte_data(struct i2c_client *c,u8 r){(void)c;return registers[r];}
static __attribute__((unused)) int i2c_smbus_write_byte_data(struct i2c_client *c,u8 r,u8 v){(void)c;registers[r]=v;writes++;return 0;}
static __attribute__((unused)) int regmap_write(int *m,unsigned int r,unsigned int v){(void)m;registers[r]=v;writes++;return 0;}
static __attribute__((unused)) int regmap_update_bits(int *m,unsigned int r,unsigned int mask,unsigned int v){unsigned int n=(registers[r]&~mask)|(v&mask);if(n!=registers[r])return regmap_write(m,r,n);return 0;}
''' + enums + "\n" + defines(dp, names=["USB_TYPEC_DP_SID"])
translations = {}
pi = (source / "pi3usb30532.c").read_text()
translations["pi"] = common + defines(pi, prefix="PI3USB30532_") + r'''
struct pi3usb30532 {struct i2c_client *client;int lock;u8 conf;};
''' + "\n".join(function(pi, name) for name in ["pi3usb30532_set_conf", "pi3usb30532_sw_set", "pi3usb30532_mux_set"]) + r'''
int main(void){struct i2c_client c={0};struct typec_altmode alt={USB_TYPEC_DP_SID};const unsigned long modes[]={TYPEC_STATE_SAFE,TYPEC_STATE_USB,TYPEC_DP_STATE_C,TYPEC_DP_STATE_D,TYPEC_DP_STATE_E};for(unsigned int b=0;b<256;b++)for(unsigned int o=0;o<3;o++)for(unsigned int m=0;m<5;m++){if(!o&&m)continue;struct pi3usb30532 p={.client=&c,.conf=b};struct typec_switch_dev sw={&p};struct typec_mux_dev mux={&p};struct typec_mux_state state={modes[m],m>1?&alt:NULL,NULL};registers[0]=b;writes=0;int a=pi3usb30532_sw_set(&sw,o);int z=pi3usb30532_mux_set(&mux,&state);printf("P %u %u %u %d %d %u %u\n",b,o,m,a,z,registers[0],writes);}return 0;}
'''
ti = (source / "tusb1046.c").read_text()
translations["ti"] = common + defines(ti, prefix="TUSB1046_") + r'''
struct tusb1046_priv {struct i2c_client *client;int general_reg_lock;};
''' + "\n".join(function(ti, name) for name in ["tusb1046_mux_set", "tusb1046_switch_set"]) + r'''
int main(void){struct i2c_client c={0};struct typec_altmode alt={USB_TYPEC_DP_SID};const unsigned long modes[]={TYPEC_STATE_SAFE,TYPEC_STATE_USB,TYPEC_DP_STATE_C,TYPEC_DP_STATE_D,TYPEC_DP_STATE_E};for(unsigned int b=0;b<256;b++)for(unsigned int o=0;o<3;o++)for(unsigned int m=0;m<5;m++){if(!o&&m)continue;struct tusb1046_priv p={.client=&c};struct typec_switch_dev sw={&p};struct typec_mux_dev mux={&p};struct typec_mux_state state={modes[m],m>1?&alt:NULL,NULL};registers[10]=b;writes=0;int a=tusb1046_switch_set(&sw,o);int z=tusb1046_mux_set(&mux,&state);printf("T %u %u %u %d %d %u %u\n",b,o,m,a,z,registers[10],writes);}return 0;}
'''
nb = (source / "nb7vpq904m.c").read_text()
nb_macros = "\n".join(match.group() for match in re.finditer(r"^#define[^\n]*", nb, re.M) if not match.group().startswith("#define DATA_LANES_COUNT"))
translations["nb"] = common + nb_macros + r'''
struct nb7vpq904m {int *regmap;bool swap_data_lanes;enum typec_orientation orientation;unsigned long mode;unsigned int svid;};
''' + "\n".join(function(nb, name) for name in ["nb7vpq904m_set_channel", "nb7vpq904m_set"]) + r'''
int main(void){int map=0;const unsigned char seeds[]={0,0x5a,0xa5,0xff};const unsigned long modes[]={TYPEC_STATE_SAFE,TYPEC_STATE_USB,TYPEC_DP_STATE_C,TYPEC_DP_STATE_D,TYPEC_DP_STATE_E,TYPEC_DP_STATE_F};for(unsigned int s=0;s<4;s++)for(unsigned int swap=0;swap<2;swap++)for(unsigned int o=1;o<3;o++)for(unsigned int m=0;m<6;m++){memset(registers,seeds[s],sizeof(registers));struct nb7vpq904m p={.regmap=&map,.orientation=o,.swap_data_lanes=swap,.mode=TYPEC_STATE_SAFE};nb7vpq904m_set(&p);p.mode=modes[m];p.svid=m>1?USB_TYPEC_DP_SID:0;int ret=nb7vpq904m_set(&p);printf("N %u %u %u %u %d ",seeds[s],swap,o,m,ret);for(unsigned int r=0;r<32;r++)printf("%02x",registers[r]);putchar('\n');}return 0;}
'''
ps = (source / "ps883x.c").read_text()
ps_extra = defines((source / "typec_tbt.h").read_text(), names=["USB_TYPEC_VENDOR_INTEL", "USB_TYPEC_TBT_SID", "TBT_CABLE_ACTIVE_PASSIVE", "TBT_ENTER_MODE_UNI_DIR_LSRX"])
ps_extra += defines((source / "pd.h").read_text(), names=["EUDO_CABLE_TYPE_MASK", "EUDO_CABLE_TYPE_PASSIVE"])
translations["ps"] = common + defines(ps, prefix="REG_USB_") + defines(ps, prefix="CONN_STATUS_") + ps_extra + r'''
struct regulator {unsigned int id;};struct gpio_desc {int value;};static unsigned int supplies,delay;
static int regulator_enable(struct regulator *r){supplies|=1U<<r->id;return 0;}
static int regulator_disable(struct regulator *r){supplies&=~(1U<<r->id);return 0;}
static void usleep_range(unsigned int lo,unsigned int hi){(void)hi;delay+=lo;}
static void msleep(unsigned int ms){delay+=ms*1000;}
static void gpiod_set_value(struct gpio_desc *g,int v){g->value=v;}
struct ps883x_retimer {struct i2c_client *client;int *regmap;struct gpio_desc *reset_gpio;struct regulator *vdd33_supply,*vdd33_cap_supply,*vdd_supply,*vddar_supply,*vddat_supply,*vddio_supply;enum typec_orientation orientation;bool in_reset;};
''' + "\n".join(function(ps, name) for name in ["ps883x_enable_vregs", "ps883x_disable_vregs", "ps883x_reset", "ps883x_configure", "ps883x_set"]) + r'''
int main(void){int map=0;struct i2c_client c={0};struct regulator rails[6]={{0},{1},{2},{3},{4},{5}};struct typec_altmode dp={USB_TYPEC_DP_SID},tb={USB_TYPEC_TBT_SID};const unsigned long modes[]={TYPEC_STATE_SAFE,TYPEC_STATE_USB,TYPEC_MODE_USB2,TYPEC_MODE_USB3,TYPEC_DP_STATE_C,TYPEC_DP_STATE_D,TYPEC_DP_STATE_E,TYPEC_STATE_MODAL,TYPEC_MODE_USB4};for(unsigned int o=0;o<3;o++)for(unsigned int m=0;m<9;m++)for(unsigned int f=0;f<4;f++){if((!o&&m!=0&&m!=2)||(m<7&&f))continue;memset(registers,0,sizeof(registers));supplies=delay=0;struct gpio_desc gpio={1};struct ps883x_retimer p={.client=&c,.regmap=&map,.reset_gpio=&gpio,.vdd33_supply=&rails[0],.vdd33_cap_supply=&rails[1],.vdd_supply=&rails[2],.vddar_supply=&rails[3],.vddat_supply=&rails[4],.vddio_supply=&rails[5],.orientation=o,.in_reset=true};struct typec_thunderbolt_data tbt={.cable_mode=(f&1)?TBT_CABLE_ACTIVE_PASSIVE:0,.enter_vdo=(f&2)?TBT_ENTER_MODE_UNI_DIR_LSRX:0};struct enter_usb_data usb={.eudo=f<<19};struct typec_retimer_state state={.mode=modes[m],.alt=(m>=4&&m<=6)?&dp:m==7?&tb:NULL,.data=m==7?(void*)&tbt:m==8?(void*)&usb:NULL};int ret=ps883x_set(&p,&state);printf("S %u %u %u %d %u %u %u %u %u %u\n",o,m,f,ret,registers[0],registers[1],registers[2],p.in_reset,supplies,delay);}return 0;}
'''
trace = bytearray()
for name, code in translations.items():
    path = out / f"{name}-oracle.c"; path.write_text(code)
    binary = out / f"{name}-oracle"
    subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer", str(path), "-o", str(binary)], check=True)
    trace.extend(subprocess.check_output([str(binary)]))
(out / "trace.txt").write_bytes(trace)
manifest = {"linux_commit": "a804c5742bff224d4cb4d25dd383554d598be32b", "sources": pins, "cases": len(trace.splitlines()), "trace_sha256": hashlib.sha256(trace).hexdigest()}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps(manifest))
