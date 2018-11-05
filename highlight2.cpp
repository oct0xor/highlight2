// Plugin for Call Instructions Highlighting (multi-architectural and without idc.set_color)
// 
// Copyright (C) 2018 oct0xor@gmail.com
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program.	If not, see <http://www.gnu.org/licenses/>.

#include <ida.hpp>
#include <idp.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

static qstrvec_t *call_mnemonics = new qstrvec_t();

static int highlight2_enabled = 1;
static int highlight2_color = COLOR_CODNAME;

static const cfgopt_t g_opts[] =
{
	cfgopt_t("HIGHLIGHT2_ENABLED", &highlight2_enabled, 0, 1),
	cfgopt_t("HIGHLIGHT2_COLOR", &highlight2_color, COLOR_DEFAULT, COLOR_FG_MAX),
};

//--------------------------------------------------------------------------
static bool highlight_calls(qflow_chart_t *fc, int n, text_t &text)
{
	if (!highlight2_enabled || n >= fc->blocks.size())
		return false;

	gen_disasm_text(text, fc->blocks[n].start_ea, fc->blocks[n].end_ea, false);

	for (int i = 0; i < text.size(); i++)
	{
		ssize_t len = text[i].line.length();
		
		if (len > 2 && text[i].line[1] == COLOR_INSN)
		{
			const char* line = text[i].line.c_str();

			for (int j = 0; j < call_mnemonics->size(); j++)
			{
				const char* instr = call_mnemonics->at(j).c_str();
				ssize_t instr_len = call_mnemonics->at(j).length();

				if (instr_len + 2 < len && 
					!memcmp(instr, line + 2, instr_len) && 
					line[2 + instr_len] == COLOR_REGCMT)
				{
					text[i].line[1] = highlight2_color;
				}
			}
		}
	}
	
	return true;
}

//--------------------------------------------------------------------------
static ssize_t idaapi ui_cb(void *user_data, int code, va_list va)
{
	switch ( code )
	{
		case ui_gen_idanode_text:
		{
			qflow_chart_t *fc = va_arg(va, qflow_chart_t *);
			int node = va_arg(va, int);
			text_t *text = va_arg(va, text_t *);
			return highlight_calls(fc, node, *text);
		}
	}
	return 0;
}

//--------------------------------------------------------------------------
static void get_call_instructions(void)
{
	if (call_mnemonics->size())
		return;

	int instruc_count = ph.instruc_end - 1 - ph.instruc_start;

	for (int i = 0; i < instruc_count; i++)
	{
		if ((ph.instruc[i].feature & CF_CALL) == CF_CALL)
		{
			call_mnemonics->push_back(qstring(ph.instruc[i].name));
		}
	}

	//for (int i = 0; i < call_mnemonics->size(); i++)
	//{
	//	msg("Highlight instruction - %s\n", call_mnemonics->at(i).c_str());
	//}
}

//--------------------------------------------------------------------------
static void load_config()
{
	read_config_file("highlight2", g_opts, qnumber(g_opts));
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
	// unload us if text mode, no graph are there
	if ( !is_idaq() )
		return PLUGIN_SKIP;

	load_config();

	get_call_instructions();

	hook_to_notification_point(HT_UI, ui_cb);

	msg("Highlight2 started\n");

	return PLUGIN_KEEP;
}

//--------------------------------------------------------------------------
void idaapi term(void)
{
	unhook_from_notification_point(HT_UI, ui_cb);
}

//--------------------------------------------------------------------------
bool idaapi run(size_t)
{
	static const char form[] =
		"Highlight2 Settings\n"
		" <Enable plugin:C>>\n"
		" <Select color:b::40::>\n"
		"\n"
		"Hint: to change this permanently, edit highlight2.cfg.\n\n";

	static const char *items[] =
	{ 
		"COLOR_DEFAULT",
		"COLOR_REGCMT",
		"COLOR_RPTCMT",
		"COLOR_AUTOCMT",
		"COLOR_INSN",
		"COLOR_DATNAME",
		"COLOR_DNAME",
		"COLOR_DEMNAME",
		"COLOR_SYMBOL",
		"COLOR_CHAR",
		"COLOR_STRING",
		"COLOR_NUMBER",
		"COLOR_VOIDOP",
		"COLOR_CREF",
		"COLOR_DREF",
		"COLOR_CREFTAIL",
		"COLOR_DREFTAIL",
		"COLOR_ERROR",
		"COLOR_PREFIX",
		"COLOR_BINPREF",
		"COLOR_EXTRA",
		"COLOR_ALTOP",
		"COLOR_HIDNAME",
		"COLOR_LIBNAME",
		"COLOR_LOCNAME",
		"COLOR_CODNAME",
		"COLOR_ASMDIR",
		"COLOR_MACRO",
		"COLOR_DSTR",
		"COLOR_DCHAR",
		"COLOR_DNUM",
		"COLOR_KEYWORD",
		"COLOR_REG",
		"COLOR_IMPNAME",
		"COLOR_SEGNAME",
		"COLOR_UNKNAME",
		"COLOR_CNAME",
		"COLOR_UNAME",
		"COLOR_COLLAPSED",
		"COLOR_FG_MAX",
	};

	qstrvec_t list;
	for (int i = 0; i < qnumber(items); i++)
		list.push_back(items[i]);

	int sel = highlight2_color - 1;
	uval_t flags = highlight2_enabled;

	if (ask_form(form, &flags, &list, &sel) > 0)
	{
		highlight2_color = sel + 1;
		highlight2_enabled = flags;
	}

	return true;
}

//--------------------------------------------------------------------------
//
//			PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,								// plugin flags
	init,							// initialize
	term,							// terminate. this pointer may be NULL.
	run,							// invoke plugin
	"Multi-architectural Call Instructions Highlighting",
	NULL,
	"Highlight2",
	NULL
};
