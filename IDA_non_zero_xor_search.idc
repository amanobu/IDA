#include <idc.idc>
static main(){
Message("non zero xor search start\n");
auto addr, end, ea, mn, opd0, opd1, attr, fname;
addr = 0;
for(addr = NextFunction(addr); addr != BADADDR; addr = NextFunction(addr)){
 end = GetFunctionAttr(addr, FUNCATTR_END);
 ea = addr;
 while(ea <= end && ea != BADADDR){
  mn = GetMnem(ea);
  if(strstr("xor", mn) == 0){
   opd0 = GetOpnd(ea, 0);
   opd1 = GetOpnd(ea, 1);
   attr = GetFunctionAttr(addr, FUNCATTR_FLAGS);
   if(strstr(opd0, opd1) != 0 && !(attr & FUNC_LIB)){
    fname = GetFunctionName(addr);
    Message("[ 0x%x ] Mnemonic: %s %s %s \t\t\t funcname:%s \t\t\t attrs:", ea, mn, opd0, opd1, fname);
	if (attr & FUNC_NORET) Message("FUNC_NORET");
	if (attr & FUNC_FAR) Message("|FUNC_FAR");
	if (attr & FUNC_LIB) Message("|FUNC_LIB");
	if (attr & FUNC_STATIC) Message("|FUNC_STATIC");
	if (attr & FUNC_FRAME) Message("|FUNC_FRAME");
	if (attr & FUNC_USERFAR) Message("|FUNC_USERFAR");
	if (attr & FUNC_HIDDEN) Message("|FUNC_HIDDEN");
	if (attr & FUNC_THUNK) Message("|FUNC_THUNK");
	if (attr & FUNC_BOTTOMBP) Message("|FUNC_BOTTOMBP");
	if (attr & FUNC_NORET_PENDING) Message("|FUNC_NORET_PENDING");
	if (attr & FUNC_SP_READY) Message("|FUNC_SP_READY");
	if (attr & FUNC_FUZZY_SP) Message("|FUNC_FUZZY_SP");
	if (attr & FUNC_PROLOG_OK) Message("|FUNC_PROLOG_OK");
	if (attr & FUNC_PURGED_OK) Message("|FUNC_PURGED_OK");
	if (attr & FUNC_TAIL) Message("|FUNC_TAIL");
	Message("\n");
   }
  }
  ea = FindCode(ea, SEARCH_DOWN|SEARCH_NEXT);
 }
}
Message("non zero xor search end\n");
}
