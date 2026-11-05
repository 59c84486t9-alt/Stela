/* SPDX-License-Identifier: GPL-2.0-only */
/* Included only by the registry fixture. Exact original setup/early bodies
 * below are an oracle separate from the candidate registry adapters. */
static const struct obs_kernel_param *reference_setup_start, *reference_setup_end;
#include <stela/registry_setup_reference.h>
struct setup_effect {
 unsigned calls, logs;
 int id[48], levels[48];
 char values[48][96], messages[48][160];
};
static struct setup_effect *effect;
static int setup_record(unsigned id, char *value, int ret)
{
 unsigned n=effect->calls++;
 assert(n<ARRAY_SIZE(effect->id)); effect->id[n]=id;
 const char *text=value ?: "<NULL>";
 assert(strlen(text)<sizeof(effect->values[n])); strcpy(effect->values[n],text);
 return ret;
}
static int setup_a(char *v) { return setup_record(1,v,-EINVAL); }
static int setup_b(char *v) { return setup_record(2,v,0); }
static int setup_bare(char *v) { return setup_record(3,v,0); }
static int setup_zero(char *v) { return setup_record(4,v,0); }
static int setup_consumed(char *v) { return setup_record(5,v,-EIO); }
static int setup_prefix(char *v) { return setup_record(6,v,1); }
static int setup_console(char *v) { return setup_record(7,v,0); }
static void setup_log(void *context,int level,const char *message)
{
 (void)context;
 unsigned n=effect->logs++;
 assert(n<ARRAY_SIZE(effect->messages) && strlen(message)<sizeof(effect->messages[n]));
 effect->levels[n]=level; strcpy(effect->messages[n],message);
}
static int original_unknown(char *param,char *val,const char *doing,void *context)
{
 (void)doing; (void)context;
 reference_repair_env_string(param,val);
 return reference_obsolete_checksetup(param) ? 0 : -ENOENT;
}
static const char *const setup_differential_inputs[] = {
 "", "same-name=abc", "same_name=\"two words\"", "bare", "bare=1",
 "bareSuffix", "prefixSuffix", "obsoleteSuffix", "unknown=\"quoted value\"",
 "same-name=abc same-name=abc", "console=ttyS0", "earlycon=x", "-- tail untouched",
 "same-name=abc unknown -- tail", "\"same-name=two words\" bare", "obsolete bare same_name=",
};
static unsigned setup_differential_index;
static void setup_differential_case(void)
{
 const struct stela_linux_services services={.log=setup_log};
 const struct stela_linux_owner owner={.services=&services};
 stela_linux_enter(&owner);
 struct registry_fixture f; fixture_init(&f);
 fixture_setup(&f,0,true,"same_name",setup_a);
 fixture_setup(&f,0,true,"same_name",setup_b);
 fixture_setup(&f,0,true,"bare",setup_bare);
 fixture_setup(&f,0,false,"same_name=",setup_zero);
 fixture_setup(&f,0,false,"same_name=",setup_consumed);
 fixture_setup(&f,0,false,"prefix",setup_prefix);
 fixture_setup(&f,0,false,"obsolete",NULL);
 fixture_setup(&f,0,true,"earlycon",setup_console);
 const char *input=setup_differential_inputs[setup_differential_index];
 size_t length=strlen(input);
 assert(length<256);
 struct setup_effect actual={}, expected={};
 effect=&actual;
 begin_fixture(&f,input);
 assert(!stela_linux_registry_early_parameters(test_registry,NULL));
 int actual_error=stela_linux_registry_initial_parameters(test_registry,NULL,NULL);
 char *actual_tail=NULL;
 assert(!stela_linux_registry_parse_result(test_registry,1,&actual_tail));
 struct obs_kernel_param table[8];
 for(unsigned i=0;i<ARRAY_SIZE(table);++i)
  table[i]=(struct obs_kernel_param){.str=f.setup[i].label,.setup_func=f.setup[i].target,
   .early=f.setup[i].header.kind==STELA_LINUX_REG_EARLY};
 reference_setup_start=table; reference_setup_end=table+ARRAY_SIZE(table);
 unsigned char early[256], initial[256];
 memset(early,0xa7,sizeof(early)); memset(initial,0xa7,sizeof(initial));
 memcpy(early,input,length+1); memcpy(initial,input,length+1);
 effect=&expected;
 char *early_result=parse_args("early options",(char *)early,NULL,0,0,0,NULL,reference_do_early_param);
 assert(!IS_ERR(early_result));
 char *expected_tail=parse_args("Booting kernel",(char *)initial,NULL,0,-1,-1,NULL,original_unknown);
 int expected_error=IS_ERR(expected_tail) ? (int)PTR_ERR(expected_tail) : 0;
 assert(actual_error==expected_error);
 assert(!memcmp(&actual,&expected,sizeof(actual)));
 assert(!memcmp(test_registry->arguments,early,length+1));
 assert(!memcmp(test_registry->arguments+test_registry->stride,initial,length+1));
 if(IS_ERR(expected_tail)) assert(PTR_ERR(actual_tail)==PTR_ERR(expected_tail));
 else if(expected_tail) {
  assert(actual_tail && actual_tail-(test_registry->arguments+test_registry->stride)==expected_tail-(char *)initial);
  assert(!strcmp(actual_tail,expected_tail));
 } else assert(!actual_tail);
 stela_linux_exit();
}
