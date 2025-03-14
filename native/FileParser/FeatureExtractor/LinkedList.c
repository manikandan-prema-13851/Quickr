#include "FeatureHeader.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>


#pragma warning(disable:4146)
#pragma warning (disable: 4996)	
#pragma warning(disable:6031)


__declspec(noinline)  struct FeatNode* createFeatNode() {
	//printf("%s \n\n", key);
	struct FeatNode* newNode = (struct FeatNode*)calloc(1, sizeof(struct FeatNode));
	if (newNode) {
		newNode->key = NULL;
		newNode->value = 0;
		newNode->next = NULL;
	}
	return newNode;
}


__declspec(noinline) void printList(struct FeatNode* node) {
	while (node != NULL) {
		printf("%s \n ", (node)->key);
		node = (node)->next;
	}
}


__declspec(noinline) void printfun(struct FeatNode** node)
{
	while (*node != NULL)
	{
		//printf("%s \n ", *node->key);
		//*node = *node->next;
	}
}


__declspec(noinline) int findlength(struct FeatNode* head) {
	struct FeatNode* curr = head;
	int cnt = 0;
	while (curr != NULL) {
		cnt++;
		curr = curr->next;
	}
	return cnt;
}


__declspec(noinline) void featNodeAppend(struct FeatNode** head_ref, char* key, float value)
{
	struct FeatNode* new_node = createFeatNode();
	new_node->value = value;
	new_node->key = (char*)calloc(strlen(key) + 1, sizeof(char));
	if (new_node->key) {
		strcpy(new_node->key, key);
	}
	struct FeatNode* last = *head_ref;

	if (*head_ref == NULL)
	{
		*head_ref = new_node;
		return;
	}

	while (last->next != NULL)
		last = last->next;

	last->next = new_node;
	return;
}


__declspec(noinline)  void freeFeatNode(struct FeatNode* head)
{
	struct FeatNode* tmp = head;

	while (head != NULL)
	{
		tmp = head;
		head = head->next;
		if (tmp->key)
			free(tmp->key);
		if (tmp)
			free(tmp);
	}
}


__declspec(noinline)  void searchInsertFeatNode(struct FeatNode** head_ref, char* key, float value) {
	int flag = 0;
	if (*head_ref == NULL) {
		featNodeAppend(head_ref, key, value);
		flag = 1;
	}
	else {
		struct FeatNode* last = *head_ref;
		while (last != NULL) {
			/*if (strcmp(last->key, key) == 0) {
				printf("valid strcmp\n");
			}*/
			//printf("%d %d %d\n ", last->key, key, strcmp(last->key, key));
			if (strcmp(last->key, key) == 0) {
				last->value += value;
				flag = 1;
				break;
			}
			last = last->next;
		}
		if (flag == 0)
			featNodeAppend(head_ref, key, value);
	}
}


__declspec(noinline)  void searchInsertFeatNodeN(struct FeatNode** head_ref, char* key, float value) {
	int flag = 0;
	if (*head_ref == NULL) {
		featNodeAppend(head_ref, key, value);
		flag = 1;
	}
	else {
		struct FeatNode* last = *head_ref;
		while (last != NULL) {
			/*if (strcmp(last->key, key) == 0) {
				printf("valid strcmp\n");
			}*/
			//printf("%d %d %d\n ", last->key, key, strcmp(last->key, key));
			if (strcmp(last->key, key) == 0) {

				flag = 1;
				break;
			}
			last = last->next;
		}
		if (flag == 0)
			featNodeAppend(head_ref, key, value);
	}
}


struct ImpFunctionMap map[1381] = {
	{"abortdoc",0},{"accept",1},{"accesscheck",2},{"accesscheckbytypeandauditalarmw",3},{"accesscheckbytyperesultlist",4},{"accesscheckbytyperesultlistandauditalarm",5},{"accessibleobjectfromwindow",6},{"activatekeyboardlayout",7},{"addaccessallowedace",8},{"addaccessallowedobjectace",9},{"addaccessdeniedace",10},{"addaccessdeniedobjectace",11},{"addace",12},{"addauditaccessace",13},{"addauditaccessobjectace",14},{"adjusttokengroups",15},{"adjusttokenprivileges",16},{"adjustwindowrectex",17},{"allocateandinitializesid",18},{"allocatelocallyuniqueid",19},{"anglearc",20},{"appendmenu",21},{"arc",22},{"arcto",23},{"areallaccessesgranted",24},{"areanyaccessesgranted",25},{"attachthreadinput",26},{"backupeventlogw",27},{"beginpaint",28},{"bind",29},{"bitblt",30},{"bringwindowtotop",31},{"clsidfromprogid",32},{"clsidfromstring",33},{"callnexthookex",34},{"callwindowproc",35},{"charlower",36},{"charlowerbuff",37},{"charnext",38},{"charprev",39},{"chartooema",40},{"charupperbuffw",41},{"charupperw",42},{"checkdlgbutton",43},{"checkmenuitem",44},{"checkremotedebuggerpresent",45},{"childwindowfrompoint",46},{"choosefonta",47},{"chord",48},{"clienttoscreen",49},{"closeclipboard",50},{"closeenhmetafile",51},{"closeeventlog",52},{"closehandle",53},{"closeprinter",54},{"closeservicehandle",55},{"closesocket",56},{"cocreateguid",57},{"cocreateinstance",58},{"cogetclassobject",59},{"coinitialize",60},{"coinitializeex",61},{"cotaskmemalloc",62},{"cotaskmemfree",63},{"cotaskmemrealloc",64},{"couninitialize",65},{"combinergn",66},{"comparefiletime",67},{"comparestring",68},{"connect",69},{"connectnamedpipe",70},{"controlservice",71},{"converttoautoinheritprivateobjectsecurity",72},{"copyenhmetafile",73},{"copyfile",74},{"copyicon",75},{"copyimage",76},{"copyrect",77},{"copysid",78},{"countclipboardformats",79},{"createacceleratortablew",80},{"createbitmap",81},{"createbrushindirect",82},{"createcompatiblebitmap",83},{"createcompatibledc",84},{"createdc",85},{"createdibsection",86},{"createdibitmap",87},{"createdialogparam",88},{"createdirectory",89},{"createenhmetafilew",90},{"createerrorinfo",91},{"createevent",92},{"createfile",93},{"createfilemapping",94},{"createfontindirect",95},{"createhalftonepalette",96},{"createic",97},{"createicon",98},{"createmenu",99},{"createmutex",100},{"createpalette",101},{"createpen",102},{"createpenindirect",103},{"createpipe",104},{"createpopupmenu",105},{"createprocess",106},{"createprocessasuser",107},{"createprocessinternal",108},{"createprocesswithtoken",109},{"createrectrgn",110},{"createremotethread",111},{"createroundrectrgn",112},{"createservice",113},{"createsolidbrush",114},{"createstreamonhglobal",115},{"createthread",116},{"createtimerqueuetimer",117},{"createtoolhelp32snapshot",118},{"createwaitabletimer",119},{"createwindowex",120},{"cryptacquirecontext",121},{"cryptbinarytostring",122},{"cryptcreatehash",123},{"cryptdecrypt",124},{"cryptderivekey",125},{"cryptdestroyhash",126},{"cryptdestroykey",127},{"cryptencrypt",128},{"cryptgenrandom",129},{"cryptgethashparam",130},{"crypthashdata",131},{"cryptreleasecontext",132},{"cryptsetkeyparam",133},{"cryptstringtobinary",134},{"debugbreak",135},{"decodepointer",136},{"decryptfile",137},{"defframeproc",138},{"defmdichildproc",139},{"defwindowproc",140},{"deletecriticalsection",141},{"deletedc",142},{"deleteenhmetafile",143},{"deletefile",144},{"deletemenu",145},{"deleteobject",146},{"deleteservice",147},{"deregistereventsource",148},{"destroyacceleratortable",149},{"destroycursor",150},{"destroyicon",151},{"destroymenu",152},{"destroywindow",153},{"deviceiocontrol",154},{"dialogboxparam",155},{"dispcallfunc",156},{"dispatchmessage",157},{"dllfunctioncall",158},{"dnsquery",159},{"documentproperties",160},{"dosdatetimetofiletime",161},{"dragacceptfiles",162},{"dragfinish",163},{"dragqueryfile",164},{"drawedge",165},{"drawfocusrect",166},{"drawframecontrol",167},{"drawicon",168},{"drawiconex",169},{"drawmenubar",170},{"drawstatew",171},{"drawtext",172},{"duplicatehandle",173},{"duplicatetoken",174},{"event_sink_addref",175},{"event_sink_queryinterface",176},{"event_sink_release",177},{"ellipse",178},{"emptyclipboard",179},{"enablemenuitem",180},{"enablescrollbar",181},{"enablewindow",182},{"encodepointer",183},{"encryptfile",184},{"enddialog",185},{"enddoc",186},{"endmenu",187},{"endpage",188},{"endpaint",189},{"entercriticalsection",190},{"enumcalendarinfo",191},{"enumchildwindows",192},{"enumclipboardformats",193},{"enumdesktopwindows",194},{"enumdevicedrivers",195},{"enumdisplaymonitors",196},{"enumfontfamiliesexw",197},{"enumfontsw",198},{"enumprinters",199},{"enumprocessmodules",200},{"enumprocesses",201},{"enumresourcenamesw",202},{"enumresourcetypesa",203},{"enumresourcetypesexa",204},{"enumsystemlocales",205},{"enumthreadwindows",206},{"enumwindows",207},{"equalrect",208},{"equalsid",209},{"excludecliprect",210},{"exitprocess",211},{"exitthread",212},{"exitwindowsex",213},{"expandenvironmentstrings",214},{"extfloodfill",215},{"exttextoutw",216},{"filetimetodosdatetime",217},{"filetimetolocalfiletime",218},{"filetimetosystemtime",219},{"fillrect",220},{"findclose",221},{"findfirstfile",222},{"findfirstfreeace",223},{"findfirsturlcacheentrya",224},{"findnextfile",225},{"findnexturlcacheentrya",226},{"findresource",227},{"findtexta",228},{"findwindow",229},{"flatsb_getscrollinfo",230},{"flatsb_getscrollpos",231},{"flatsb_setscrollinfo",232},{"flatsb_setscrollpos",233},{"flatsb_setscrollprop",234},{"flushefscache",235},{"flushfilebuffers",236},{"flushinstructioncache",237},{"formatmessagea",238},{"formatmessagew",239},{"framerect",240},{"framergn",241},{"freeconsole",242},{"freeenvironmentstrings",243},{"freelibrary",244},{"freeresource",245},{"freesid",246},{"ftpputfilea",247},{"gdiflush",248},{"getacp",249},{"getace",250},{"getaclinformation",251},{"getactiveobject",252},{"getactivewindow",253},{"getadaptersinfo",254},{"getasynckeystate",255},{"getbitmapbits",256},{"getbrushorgex",257},{"getcpinfo",258},{"getcapture",259},{"getclassinfo",260},{"getclasslongw",261},{"getclassname",262},{"getclientrect",263},{"getclipbox",264},{"getclipboarddata",265},{"getcommandline",266},{"getcomputername",267},{"getconsolecp",268},{"getconsolemode",269},{"getconsoleoutputcp",270},{"getconsolewindow",271},{"getcurrentdirectory",272},{"getcurrenthwprofilea",273},{"getcurrentobject",274},{"getcurrentpositionex",275},{"getcurrentprocess",276},{"getcurrentprocessid",277},{"getcurrentthread",278},{"getcurrentthreadid",279},{"getcursor",280},{"getcursorpos",281},{"getdc",282},{"getdcorgex",283},{"getdcpencolor",284},{"getdibcolortable",285},{"getdibits",286},{"getdateformat",287},{"getdefaultprinterw",288},{"getdesktopwindow",289},{"getdevicecaps",290},{"getdiskfreespace",291},{"getdlgctrlid",292},{"getdlgitem",293},{"getdlgitemtext",294},{"getdrivetype",295},{"getenhmetafilebits",296},{"getenhmetafiledescriptionw",297},{"getenhmetafileheader",298},{"getenhmetafilepaletteentries",299},{"getenvironmentstrings",300},{"getenvironmentvariable",301},{"geterrorinfo",302},{"getexitcodeprocess",303},{"getexitcodethread",304},{"getfileattributes",305},{"getfileinformationbyhandle",306},{"getfilesize",307},{"getfiletime",308},{"getfiletype",309},{"getfileversioninfo",310},{"getfileversioninfosize",311},{"getfocus",312},{"getforegroundwindow",313},{"getfullpathname",314},{"geticoninfo",315},{"getipnettable",316},{"getkeynametext",317},{"getkeystate",318},{"getkeyboardlayout",319},{"getkeyboardlayoutlist",320},{"getkeyboardlayoutnamew",321},{"getkeyboardstate",322},{"getkeyboardtype",323},{"getkeynametexta",324},{"getlastactivepopup",325},{"getlasterror",326},{"getlengthsid",327},{"getlocaltime",328},{"getlocaleinfo",329},{"getlogicaldrives",330},{"getlogicalprocessorinformation",331},{"getmenu",332},{"getmenucheckmarkdimensions",333},{"getmenuitemcount",334},{"getmenuitemid",335},{"getmenuiteminfo",336},{"getmenustate",337},{"getmenustring",338},{"getmessagea",339},{"getmessageextrainfo",340},{"getmessagepos",341},{"getmessagetime",342},{"getmessagew",343},{"getmodulebasenamea",344},{"getmodulefilename",345},{"getmodulehandle",346},{"getmonitorinfow",347},{"getnativesysteminfo",348},{"getnearestpaletteindex",349},{"getoemcp",350},{"getobject",351},{"getopenfilenamea",352},{"getpaletteentries",353},{"getparent",354},{"getpixel",355},{"getprivateprofilestrin",356},{"getpro",357},{"getprocaddress",358},{"getprocessheap",359},{"getprocessid",360},{"getprocessidofthread",361},{"getprofileinta",362},{"getprofilestringa",363},{"getrawinputdata",364},{"getrgnbox",365},{"getsavefilenamea",366},{"getscrollbarinfo",367},{"getscrollinfo",368},{"getscrollpos",369},{"getscrollrange",370},{"getsecuritydescriptordacl",371},{"getshortpathname",372},{"getstartupinfo",373},{"getstdhandle",374},{"getstockobject",375},{"getstretchbltmode",376},{"getstringtype",377},{"getsubmenu",378},{"getsyscolor",379},{"getsyscolorbrush",380},{"getsystemdefaultlangid",381},{"getsystemdefaultuilanguage",382},{"getsystemdirectory",383},{"getsysteminfo",384},{"getsystemmenu",385},{"getsystemmetrics",386},{"getsystempaletteentries",387},{"getsystemtime",388},{"getsystemtimeasfiletime",389},{"gettempfilename",390},{"gettemppath",391},{"gettextcolor",392},{"gettextextentpoint",393},{"gettextmetrics",394},{"getthreadcontext",395},{"getthreadid",396},{"getthreadinformation",397},{"getthreadlocale",398},{"getthreadpriority",399},{"gettickcount",400},{"gettimeformatw",401},{"gettimezoneinformation",402},{"gettokeninformation",403},{"gettopwindow",404},{"getuserdefaultlcid",405},{"getuserdefaultlangid",406},{"getuserdefaultuilanguage",407},{"getusername",408},{"getversion",409},{"getvolumeinformationw",410},{"getwinmetafilebits",411},{"getwindow",412},{"getwindowdc",413},{"getwindowlonga",414},{"getwindowlongw",415},{"getwindowmodulefilenamew",416},{"getwindoworgex",417},{"getwindowplacement",418},{"getwindowrect",419},{"getwindowtexta",420},{"getwindowtextlengthw",421},{"getwindowtextw",422},{"getwindowthreadprocessid",423},{"getwindowsdirectorya",424},{"getwindowsdirectoryw",425},{"gethostbyname",426},{"gethostname",427},{"globaladdatom",428},{"globalalloc",429},{"globaldeleteatom",430},{"globalfindatom",431},{"globalfree",432},{"globalhandle",433},{"globallock",434},{"globalrealloc",435},{"globalsize",436},{"globalunlock",437},{"heapalloc",438},{"heapcreate",439},{"heapdestroy",440},{"heapfree",441},{"heaprealloc",442},{"heapsetinformation",443},{"heapsize",444},{"hidecaret",445},{"httpaddrequestheaders",446},{"httpopenrequest",447},{"httpsendrequestw",448},{"icmpsendecho",449},{"imagelist_add",450},{"imagelist_addmasked",451},{"imagelist_begindrag",452},{"imagelist_copy",453},{"imagelist_create",454},{"imagelist_destroy",455},{"imagelist_dragenter",456},{"imagelist_dragleave",457},{"imagelist_dragmove",458},{"imagelist_dragshownolock",459},{"imagelist_draw",460},{"imagelist_drawex",461},{"imagelist_enddrag",462},{"imagelist_getbkcolor",463},{"imagelist_getdragimage",464},{"imagelist_geticon",465},{"imagelist_geticonsize",466},{"imagelist_getimagecount",467},{"imagelist_getimageinfo",468},{"imagelist_loadimagew",469},{"imagelist_read",470},{"imagelist_remove",471},{"imagelist_replace",472},{"imagelist_replaceicon",473},{"imagelist_setbkcolor",474},{"imagelist_setdragcursorimage",475},{"imagelist_seticonsize",476},{"imagelist_setimagecount",477},{"imagelist_setoverlayimage",478},{"imagelist_write",479},{"impersonateloggedonuser",480},{"inet_addr",481},{"inflaterect",482},{"initcommoncontrols",483},{"initcommoncontrolsex",484},{"initializeacl",485},{"initializecriticalsection",486},{"initializecriticalsectionandspincount",487},{"initializeflatsb",488},{"initializeslisthead",489},{"initializesecuritydescriptor",490},{"insertmenu",491},{"insertmenuitem",492},{"interlockedcompareexchange",493},{"interlockeddecrement",494},{"interlockedexchange",495},{"interlockedincrement",496},{"interlockedpopentryslist",497},{"interlockedpushentryslist",498},{"internetclosehandle",499},{"internetconnect",500},{"internetcrackurlw",501},{"internetopen",502},{"internetopenurla",503},{"internetreadfile",504},{"internetreadfileexa",505},{"internetsetoptiona",506},{"internetwritefile",507},{"intersectcliprect",508},{"intersectrect",509},{"invalidaterect",510},{"invalidatergn",511},{"isaccelerator",512},{"ischild",513},{"isclipboardformatavailable",514},{"isdebuggerpresent",515},{"isdialogmessage",516},{"isdlgbuttonchecked",517},{"isequalguid",518},{"isiconic",519},{"isprocessorfeaturepresent",520},{"isrectempty",521},{"isvalidacl",522},{"isvalidcodepage",523},{"isvalidlocale",524},{"iswindow",525},{"iswindowenabled",526},{"iswindowunicode",527},{"iswindowvisible",528},{"iswow64process",529},{"iszoomed",530},{"keinsertqueueapc",531},{"killtimer",532},{"lcmapstringa",533},{"lcmapstringw",534},{"lptodp",535},{"ldrloaddll",536},{"leavecriticalsection",537},{"lineto",538},{"listen",539},{"loadbitmap",540},{"loadcursor",541},{"loadicon",542},{"loadimage",543},{"loadkeyboardlayout",544},{"loadlibrary",545},{"loadregtypelib",546},{"loadresource",547},{"loadstring",548},{"loadtypelib",549},{"localalloc",550},{"localfiletimetofiletime",551},{"localfree",552},{"lockresource",553},{"lookupaccountnamea",554},{"lookupaccountsidw",555},{"lookupprivilegenamew",556},{"lookupprivilegevalue",557},{"lresultfromobject",558},{"mapviewoffile",559},{"mapvirtualkey",560},{"mapwindowpoints",561},{"maskblt",562},{"messagebeep",563},{"messagebox",564},{"messageboxindirect",565},{"module32first",566},{"module32next",567},{"monitorfrompoint",568},{"monitorfromrect",569},{"monitorfromwindow",570},{"movefile",571},{"movetoex",572},{"movewindow",573},{"msgwaitformultipleobjects",574},{"msgwaitformultipleobjectsex",575},{"muldiv",576},{"multibytetowidechar",577},{"netapibufferfree",578},{"netshareadd",579},{"netsharecheck",580},{"netshareenum",581},{"netsharegetinfo",582},{"netsharesetinfo",583},{"netwkstagetinfo",584},{"notifywinevent",585},{"ntadjustprivilegestoken",586},{"ntallocatevirtualmemory",587},{"ntclose",588},{"ntcontinue",589},{"ntcreatefile",590},{"ntcreateprocess",591},{"ntcreatesection",592},{"ntcreatethread",593},{"ntcreateuserprocess",594},{"ntdelayexecution",595},{"ntdeletekey",596},{"ntdeletevaluekey",597},{"ntduplicateobject",598},{"ntmaketemporaryobject",599},{"ntmapviewofsection",600},{"ntopenprocess",601},{"ntopenthread",602},{"ntprotectvirtualmemory",603},{"ntquerydirectoryfile",604},{"ntqueryinformationprocess",605},{"ntquerysystemenvironmentvalueex",606},{"ntquerytimer",607},{"ntqueueapcthread",608},{"ntreadvirtualmemory",609},{"ntresumeprocess",610},{"ntresumethread",611},{"ntsetcontextthread",612},{"ntsetinformationprocess",613},{"ntsetinformationthread",614},{"ntsetsystemenvironmentvalueex",615},{"ntsetvaluekey",616},{"ntshutdownsystem",617},{"ntsuspendprocess",618},{"ntterminateprocess",619},{"ntterminatethread",620},{"ntunmapviewofsection",621},{"ntwaitformultipleobjects",622},{"ntwaitforsingleobject",623},{"ntwritevirtualmemory",624},{"oemtochara",625},{"offsetrect",626},{"olecreatefontindirect",627},{"oledraw",628},{"oleinitialize",629},{"olelockrunning",630},{"oleregenumverbs",631},{"olesetmenudescriptor",632},{"oleuninitialize",633},{"openclipboard",634},{"openfilemappinga",635},{"openprinter",636},{"openprocess",637},{"openprocesstoken",638},{"openscmanager",639},{"openservicea",640},{"openthread",641},{"outputdebugstring",642},{"pagesetupdlga",643},{"patblt",644},{"pathaddbackslashw",645},{"pathappendw",646},{"pathfileexists",647},{"peekmessage",648},{"peeknamedpipe",649},{"pie",650},{"playenhmetafile",651},{"polybezier",652},{"polybezierto",653},{"polygon",654},{"polyline",655},{"postmessage",656},{"postquitmessage",657},{"postthreadmessage",658},{"printdlga",659},{"process32first",660},{"process32next",661},{"progidfromclsid",662},{"ptinrect",663},{"queryperformancecounter",664},{"queryperformancefrequency",665},{"queueuserapc",666},{"raiseexception",667},{"readconsolew",668},{"readfile",669},{"readprocessmemory",670},{"realizepalette",671},{"rectvisible",672},{"rectangle",673},{"recv",674},{"redrawwindow",675},{"regclosekey",676},{"regconnectregistry",677},{"regcopytreea",678},{"regcreatekey",679},{"regcreatekeytransacteda",680},{"regdeletekey",681},{"regdeletekeytransacteda",682},{"regdeletekeyvaluea",683},{"regdeletekeyw",684},{"regdeletetreea",685},{"regdeletevalue",686},{"regenumkey",687},{"regenumvalue",688},{"regflushkey",689},{"reggetkeysecurity",690},{"reggetvaluea",691},{"regloadkey",692},{"regloadmuistringa",693},{"regopencurrentuser",694},{"regopenkey",695},{"regopenkeytransacteda",696},{"regopenkeyw",697},{"regopenuserclassesroot",698},{"regoverridepredefkey",699},{"regqueryinfokey",700},{"regquerymultiplevaluesa",701},{"regqueryvalueex",702},{"regreplacekey",703},{"regrestorekey",704},{"regsavekey",705},{"regsetkeysecurity",706},{"regsetkeyvaluea",707},{"regsetvalueex",708},{"regunloadkey",709},{"registerclass",710},{"registerclipboardformat",711},{"registereventsourcew",712},{"registerhotkey",713},{"registerrawinputdevices",714},{"registerwindowmessage",715},{"releasecapture",716},{"releasedc",717},{"releasemutex",718},{"releasesemaphore",719},{"removedirectory",720},{"removemenu",721},{"removeprop",722},{"replacetexta",723},{"reporteventw",724},{"resetevent",725},{"restoredc",726},{"resumethread",727},{"roundrect",728},{"rtlcopymemory",729},{"rtlcreateheap",730},{"rtlgetversion",731},{"rtlmovememory",732},{"rtlsetprocessiscritical",733},{"rtlunwind",734},{"shbrowseforfolder",735},{"shfileoperation",736},{"shgetfileinfo",737},{"shgetfolderpath",738},{"shgetmalloc",739},{"shgetpathfromidlist",740},{"shgetspecialfolderlocation",741},{"shgetspecialfolderpathw",742},{"safearrayaccessdata",743},{"safearraycreate",744},{"safearraygetelement",745},{"safearraygetlbound",746},{"safearraygetubound",747},{"safearrayptrofindex",748},{"safearrayputelement",749},{"safearrayunaccessdata",750},{"savedc",751},{"screentoclient",752},{"scrollwindow",753},{"searchpath",754},{"select",755},{"selectcliprgn",756},{"selectobject",757},{"selectpalette",758},{"send",759},{"senddlgitemmessage",760},{"sendmessage",761},{"sendmessagecallbacka",762},{"sendmessagetimeout",763},{"sendnotifymessagea",764},{"setabortproc",765},{"setactivewindow",766},{"setbkcolor",767},{"setbkmode",768},{"setbrushorgex",769},{"setcapture",770},{"setclasslong",771},{"setclipboarddata",772},{"setcurrentdirectory",773},{"setcursor",774},{"setcursorpos",775},{"setdcpencolor",776},{"setdibcolortable",777},{"setdibits",778},{"setdlgitemtext",779},{"setendoffile",780},{"setenhmetafilebits",781},{"setenvironmentvariable",782},{"seterrorinfo",783},{"seterrormode",784},{"setevent",785},{"setfileattributes",786},{"setfilepointer",787},{"setfilesecuritya",788},{"setfiletime",789},{"setfocus",790},{"setforegroundwindow",791},{"sethandlecount",792},{"setlasterror",793},{"setlayeredwindowattributes",794},{"setmapmode",795},{"setmenu",796},{"setmenuiteminfo",797},{"setparent",798},{"setpixel",799},{"setprocessdeppolicy",800},{"setprop",801},{"setrop2",802},{"setrect",803},{"setrectrgn",804},{"setscrollinfo",805},{"setscrollpos",806},{"setscrollrange",807},{"setsecuritydescriptordacl",808},{"setstdhandle",809},{"setstretchbltmode",810},{"settextcolor",811},{"setthreadcontext",812},{"setthreadlocale",813},{"setthreadpriority",814},{"setthreadtoken",815},{"settimer",816},{"setunhandledexceptionfilter",817},{"setviewportorgex",818},{"setwaitabletimer",819},{"setwineventhook",820},{"setwinmetafilebits",821},{"setwindowlong",822},{"setwindowlongptra",823},{"setwindoworgex",824},{"setwindowplacement",825},{"setwindowpos",826},{"setwindowrgn",827},{"setwindowtext",828},{"setwindowshook",829},{"shellexecute",830},{"shell_notifyiconw",831},{"showcaret",832},{"showcursor",833},{"showownedpopups",834},{"showscrollbar",835},{"showwindow",836},{"signalobjectandwait",837},{"sizeofresource",838},{"sleep",839},{"socket",840},{"startdoc",841},{"startpage",842},{"startservicea",843},{"startservicectrldispatchera",844},{"stretchblt",845},{"stretchdibits",846},{"stringfromclsid",847},{"stringfromguid2",848},{"suspendthread",849},{"switchtothread",850},{"sysallocstring",851},{"sysallocstringbytelen",852},{"sysallocstringlen",853},{"sysfreestring",854},{"sysreallocstringlen",855},{"sysstringbytelen",856},{"sysstringlen",857},{"systemparametersinfo",858},{"systemtimetofiletime",859},{"terminateprocess",860},{"terminatethread",861},{"textouta",862},{"textoutw",863},{"thread32first",864},{"thread32next",865},{"timegettime",866},{"tlsalloc",867},{"tlsfree",868},{"tlsgetvalue",869},{"tlssetvalue",870},{"toolhelp32readprocessmemory",871},{"trackpopupmenu",872},{"translatemdisysaccel",873},{"translatemessage",874},{"tryentercriticalsection",875},{"urldownloadtocachefile",876},{"urldownloadtofile",877},{"urlopenblockingstream",878},{"urlopenstream",879},{"unhandledexceptionfilter",880},{"unhookwindowshookex",881},{"unmapviewoffile",882},{"unrealizeobject",883},{"unregisterclass",884},{"updatewindow",885},{"urlescapew",886},{"urlunescapew",887},{"uuidfromstringa",888},{"varbstrcat",889},{"varbstrcmp",890},{"varui4fromstr",891},{"variantchangetype",892},{"variantclear",893},{"variantcopy",894},{"variantcopyind",895},{"variantinit",896},{"verqueryvalue",897},{"versetconditionmask",898},{"verifyversioninfow",899},{"virtualalloc",900},{"virtualalloc2fromapp",901},{"virtualallocexnuma",902},{"virtualallocfromapp",903},{"virtualfree",904},{"virtualprotect",905},{"virtualprotectfromapp",906},{"virtualquery",907},{"wnetaddconnection",908},{"wnetcloseenum",909},{"wnetenumresourcea",910},{"wnetopenenuma",911},{"wsacleanup",912},{"wsagetlasterror",913},{"wsaioctl",914},{"wsasocketa",915},{"wsastartup",916},{"waitformultipleobjects",917},{"waitforsingleobject",918},{"waitmessage",919},{"widechartomultibyte",920},{"winexec",921},{"winhelpa",922},{"winhttpopen",923},{"windowfrompoint",924},{"wow64setthreadcontext",925},{"writeconsole",926},{"writefile",927},{"writeprivateprofilestringa",928},{"writeprivateprofilestringw",929},{"writeprocessmemory",930},{"_ciatan",931},{"_cicos",932},{"_ciexp",933},{"_cilog",934},{"_cisin",935},{"_cisqrt",936},{"_citan",937},{"_corexemain",938},{"_cordllmain",938}, {"_trackmouseevent",939},{"_xcptfilter",940},{"__getmainargs",941},{"__p__commode",942},{"__p__fmode",943},{"__set_app_type",944},{"__setusermatherr",945},{"__vbachkstk",946},{"__vbaexcepthandler",947},{"__vbafpexception",948},{"__vbafreeobj",949},{"__vbafreestr",950},{"__vbafreevar",951},{"__vbafreevarlist",952},{"__vbahresultcheckobj",953},{"__vbanew2",954},{"__vbasetsystemerror",955},{"__vbastrmove",956},{"__vbavarmove",957},{"_adj_fdiv_",958},{"_adj_fdivr_m",959},{"_adj_fpatan",960},{"_adj_fprem",961},{"_adj_fptan",962},{"_allmul",963},{"_controlfp",964},{"_initterm",965},{"_onexit",966},{"deleteurlcacheentrya",967},{"enumservicesstatusa",968},{"rtldecompressbuffer",969},{"cryptunprotectdata",970},{"exit",971},{"free",972},{"htons",975},{"ioctlsocket",977},{"lstrcat",979},{"lstrcmp",980},{"lstrcpy",981},{"lstrlen",982},{"malloc",983},{"memcpy",984},{"memset",985},{"ntohs",986},{"setsockopt",990},{"sndplaysoundw",991},{"timesetevent",994},{"wsprintf",995},{"wvsprintfw",996},{"accesscheckbytyperesultlistandauditalarmw",3},{"accesscheckbytyperesultlistandauditalarma",3},{"addaccessallowedaceex",8},{"addaccessdeniedaceex",10},{"addauditaccessaceex",13},{"appendmenuw",21},{"appendmenua",21},{"callwindowprocw",35},{"callwindowproca",35},{"charlowerw",36},{"charlowerbuffw",37},{"charlowerbuffa",37},{"charlowera",36},{"charnextw",38},{"charnexta",38},{"charprevw",39},{"charpreva",39},{"comparestringw",68},{"comparestringa",68},{"wnetaddconnectiona",908},{"wnetaddconnection2a",908},{"regconnectregistryw",677},{"regconnectregistrya",677},{"internetconnectw",500},{"internetconnecta",500},{"controlserviceexa",71},{"copyenhmetafilew",73},{"copyenhmetafilea",73},{"copyfilew",74},{"copyfileexa",74},{"copyfilea",74},{"copyfile2",74},{"createdcw",85},{"createdca",85},{"createdialogparamw",88},{"createdialogparama",88},{"createdirectoryw",89},{"createdirectorya",89},{"createeventw",92},{"createeventa",92},{"createfilew",93},{"createfilemappingw",94},{"createfilemappinga",94},{"createfilea",93},{"createfile2",93},{"createfontindirectw",95},{"createfontindirecta",95},{"createicw",97},{"createica",97},{"createmutexw",100},{"createmutexexa",100},{"createmutexa",100},{"ntcreateprocessex",591},{"createprocesswithtokenw",109},{"createprocessw",106},{"createprocessasuserw",107},{"createprocessasusera",107},{"createprocessa",106},{"createremotethreadex",111},{"createservicea",113},{"ntcreatethreadex",116},{"createwindowexw",120},{"createwindowexa",120},{"cryptacquirecontextw",121},{"cryptacquirecontexta",121},{"decryptfilea",137},{"defframeprocw",138},{"defframeproca",138},{"defmdichildprocw",139},{"defmdichildproca",139},{"defwindowprocw",140},{"defwindowproca",140},{"deletefilew",144},{"deletefilea",144},{"dialogboxparamw",155},{"dialogboxparama",155},{"dispatchmessagew",157},{"dispatchmessagea",157},{"dnsquery_a",159},{"dnsqueryex",159},{"documentpropertiesw",160},{"documentpropertiesa",160},{"dragqueryfilew",164},{"dragqueryfilea",164},{"drawtextw",172},{"drawtextexw",172},{"drawtextexa",172},{"drawtextex",172},{"drawtexta",172},{"duplicatetokenex",174},{"encryptfilea",184},{"enumcalendarinfow",191},{"enumcalendarinfoa",191},{"enumprintersw",199},{"enumprintersa",199},{"enumprocessmodulesex",200},{"enumsystemlocalesw",205},{"enumsystemlocalesa",205},{"expandenvironmentstringsw",214},{"expandenvironmentstringsa",214},{"findfirstfilew",222},{"findfirstfileexw",222},{"findfirstfileexa",222},{"findfirstfilea",222},{"findnextfilew",225},{"findnextfilea",225},{"findresourcew",227},{"findresourceexw",227},{"findresourceexa",227},{"findresourcea",227},{"findwindoww",229},{"findwindowexw",229},{"findwindowexa",229},{"findwindowa",229},{"freeenvironmentstringsw",243},{"freeenvironmentstringsa",243},{"getcpinfoexw",258},{"getclassinfow",260},{"getclassinfoexw",260},{"getclassinfoa",260},{"getclassnamew",262},{"getclassnamea",262},{"getcommandlinew",266},{"getcommandlinea",266},{"getcomputernamew",267},{"getcomputernamea",267},{"getcurrentdirectoryw",272},{"getcurrentdirectorya",272},{"getdcex",282},{"getdateformatw",287},{"getdateformata",287},{"getdiskfreespacew",291},{"getdiskfreespacea",291},{"getdlgitemtextw",293},{"getdlgitemtexta",293},{"getdrivetypew",295},{"getdrivetypea",295},{"getenvironmentstringsw",300},{"getenvironmentvariablew",301},{"getenvironmentvariablea",301},{"getfileattributesw",305},{"getfileattributesa",305},{"getfileversioninfow",310},{"getfileversioninfosizew",310},{"getfileversioninfosizea",310},{"getfileversioninfoa",310},{"getfullpathnamew",314},{"getfullpathnamea",314},{"getkeynametextw",317},{"getlocaleinfow",329},{"getlocaleinfoa",329},{"getlogicalprocessorinformationex",331},{"getmenustringw",338},{"getmenustringa",338},{"getmenuiteminfow",336},{"getmenuiteminfoa",336},{"getmodulefilenamew",345},{"getmodulefilenameexa",345},{"getmodulefilenamea",345},{"getmodulehandlew",346},{"getmodulehandleexw",346},{"getmodulehandlea",346},{"getobjectw",351},{"getobjecta",351},{"getprivateprofilestringw",356},{"getprivateprofilestringa",356},{"getpropw",357},{"getpropa",357},{"getprocessheaps",357},{"getshortpathnamew",372},{"getshortpathnamea",372},{"getstartupinfow",373},{"getstartupinfoa",373},{"getstringtypew",377},{"getstringtypeexa",377},{"getstringtypea",377},{"getsystemdirectoryw",383},{"getsystemdirectorya",383},{"gettempfilenamew",390},{"gettempfilenamea",390},{"gettemppathw",391},{"gettemppatha",391},{"gettextextentpointw",393},{"gettextextentpointa",393},{"gettextextentpoint32w",393},{"gettextextentpoint32a",393},{"gettextmetricsw",394},{"gettextmetricsa",394},{"gettickcount64",400},{"getusernamew",408},{"getusernamea",408},{"getversionexw",409},{"getversionexa",409},{"globaladdatomw",428},{"globaladdatoma",428},{"globalfindatomw",431},{"globalfindatoma",431},{"httpopenrequestw",447},{"httpopenrequesta",447},{"insertmenuw",491},{"insertmenuitemw",492},{"insertmenuitema",492},{"insertmenua",491},{"internetopenw",502},{"internetopena",502},{"isdialogmessagew",516},{"isdialogmessagea",516},{"loadbitmapw",540},{"loadbitmapa",540},{"loadcursorw",541},{"loadcursora",541},{"loadiconw",542},{"loadicona",542},{"loadimagew",543},{"loadimagea",543},{"loadkeyboardlayoutw",544},{"loadkeyboardlayouta",544},{"loadlibraryw",545},{"loadlibraryexw",545},{"loadlibraryexa",545},{"loadlibrarya",545},{"loadstringw",548},{"loadstringa",548},{"lookupprivilegevaluew",557},{"lookupprivilegevaluea",557},{"mapviewoffileex",559},{"mapviewoffile3",559},{"mapviewoffile2",559},{"mapvirtualkeyw",560},{"mapvirtualkeyexa",560},{"mapvirtualkeya",560},{"messageboxw",564},{"messageboxindirectw",564},{"messageboxindirecta",564},{"messageboxa",564},{"movefilew",571},{"movefileexw",571},{"movefileexa",571},{"movefilea",571},{"ntqueueapcthreadex2",608},{"ntqueueapcthreadex",608},{"ntreadvirtualmemoryex",609},{"openprinterw",636},{"openprintera",636},{"openscmanagerw",639},{"openscmanagera",639},{"outputdebugstringw",642},{"outputdebugstringa",642},{"pathfileexistsw",647},{"pathfileexistsa",647},{"peekmessagew",648},{"peekmessagea",648},{"postmessagew",656},{"postmessagea",656},{"postthreadmessagew",658},{"postthreadmessagea",658},{"process32firstw",660},{"process32nextw",661},{"regcreatekeyexw",679},{"regcreatekeyexa",679},{"regcreatekeya",679},{"regdeletekeyexa",681},{"regdeletekeya",681},{"regdeletevaluew",686},{"regdeletevaluea",686},{"regenumkeyw",687},{"regenumkeyexw",687},{"regenumkeyexa",687},{"regenumkeya",687},{"regenumvaluew",688},{"regenumvaluea",688},{"regloadkeyw",692},{"regloadkeya",692},{"regopenkeyexw",695},{"regopenkeyexa",695},{"regopenkeya",695},{"regqueryinfokeyw",700},{"regqueryinfokeya",700},{"regqueryvalueexw",702},{"regqueryvalueexa",702},{"regreplacekeyw",703},{"regreplacekeya",703},{"regrestorekeyw",704},{"regrestorekeya",704},{"regsavekeyw",705},{"regsavekeyexa",705},{"regsavekeya",705},{"regsetvalueexw",708},{"regsetvalueexa",708},{"regunloadkeyw",709},{"regunloadkeya",709},{"registerclassw",710},{"registerclassexw",710},{"registerclassa",710},{"registerclipboardformatw",711},{"registerclipboardformata",711},{"registerwindowmessagew",715},{"registerwindowmessagea",715},{"removedirectoryw",720},{"removedirectorya",720},{"removepropw",722},{"removepropa",722},{"shbrowseforfolderw",735},{"shbrowseforfoldera",735},{"shfileoperationw",736},{"shfileoperationa",736},{"shgetfileinfow",737},{"shgetfileinfoa",737},{"shgetfolderpathw",738},{"shgetfolderpatha",738},{"shgetpathfromidlistw",740},{"shgetpathfromidlista",740},{"searchpathw",754},{"searchpatha",754},{"sendmessagew",761},{"sendmessagetimeoutw",763},{"sendmessagetimeouta",763},{"sendmessagea",761},{"senddlgitemmessagew",760},{"senddlgitemmessagea",760},{"httpsendrequestexa",448},{"httpsendrequesta",448},{"setclasslongw",771},{"setclasslonga",771},{"setcurrentdirectoryw",773},{"setcurrentdirectorya",773},{"setdlgitemtextw",779},{"setdlgitemtexta",779},{"setenvironmentvariablew",782},{"setenvironmentvariablea",782},{"setfileattributesw",786},{"setfileattributesa",786},{"setfilepointerex",787},{"setmenuiteminfow",797},{"setmenuiteminfoa",797},{"setpropw",801},{"setpropa",801},{"setwindowlongw",822},{"setwindowlonga",822},{"setwindowtextw",828},{"setwindowtexta",828},{"setwindowshookexw",829},{"setwindowshookexa",829},{"shellexecutew",830},{"shellexecuteexw",830},{"shellexecuteexa",830},{"shellexecutea",830},{"sleepex",839},{"startdocw",841},{"startdoca",841},{"systemparametersinfow",858},{"systemparametersinfoa",858},{"unregisterclassw",884},{"unregisterclassa",884},{"verqueryvaluew",897},{"verqueryvaluea",897},{"virtualallocex",900},{"virtualalloc2",900},{"virtualprotectex",905},{"virtualqueryex",907},{"waitformultipleobjectsex",917},{"waitforsingleobjectex",918},{"writeconsolew",926},{"writeconsolea",926},{"_adj_fdiv_r",958},{"_adj_fdiv_m64",958},{"_adj_fdiv_m32i",958},{"_adj_fdiv_m32",958},{"_adj_fdiv_m16i",958},{"_adj_fdivr_m64",959},{"_adj_fdivr_m32i",959},{"_adj_fdivr_m32",959},{"_adj_fdivr_m16i",959},{"_adj_fprem1",961},{"_exit",971},{"_cexit",971},{"lstrcatw",979},{"lstrcata",979},{"lstrcmpiw",980},{"lstrcmpia",980},{"lstrcmpi",980},{"lstrcmpw",980},{"lstrcmpa",980},{"lstrcpynw",981},{"lstrcpyna",981},{"lstrcpyn",981},{"lstrcpyw",981},{"lstrcpya",981},{"lstrlenw",982},{"lstrlena",982},{"wsprintfw",995},{"wsprintfa",995}
};


/* MALWARE IMPORT FUNCTION START */


__declspec(noinline)   int storeHash(char* key) {
	return key[0] % 256;
}


__declspec(noinline)  void insertMalwareFullFunc(struct hashTableMalwareFullFunc* ht, char* key, int value) {
	int pos = storeHash((char*)key);
	//printf("insert %s==> %d\n", key, pos);
	struct entryMalwareFullFunc* new_entry = (struct entryMalwareFullFunc*)calloc(1, sizeof(struct entryMalwareFullFunc));
	if (new_entry) {
		new_entry->key = (char*)calloc(sizeof(char) * (strlen(key) + 1), sizeof(char));
		if (new_entry->key) {
			memcpy(new_entry->key, key, strlen(key) + 1);
			new_entry->value = value;
			new_entry->next = ht->valueEntry[pos];
			ht->valueEntry[pos] = new_entry;
		}
	}
}


__declspec(noinline)  int retrieveMalwareFullFunc(struct hashTableMalwareFullFunc* ht, char* key) {
	int pos = storeHash((char*)key);
	//printf("retreive %s==> %d \n", key,pos);
	if (pos < 0 || pos>256) {
		return -1;
	}
	struct entryMalwareFullFunc* current = ht->valueEntry[pos];
	while (current) {
		if (strcmp(current->key, key) == 0) {
			return current->value;
		}
		current = current->next;
	}

	return -1;
}


__declspec(noinline)  void InitMalwareFullFunc(struct hashTableMalwareFullFunc* mapMalwareFullFunc) {


	if(mapMalwareFullFunc != NULL){
		memset(mapMalwareFullFunc->valueEntry, 0, sizeof(mapMalwareFullFunc->valueEntry));

		for (int i = 0; i < 1381; i++) {
			struct ImpFunctionMap imp = map[i];
			insertMalwareFullFunc(mapMalwareFullFunc, (char*)imp.key, imp.value);
		}
	}
}


/* MALWARE IMPORT FUNCTION END */