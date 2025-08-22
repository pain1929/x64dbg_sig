#include "pluginmain.h"
#include "plugin.h"

// NOTE: This is mostly just boilerplate code, generally you work in plugin.cpp
// Reference: https://help.x64dbg.com/en/latest/developers/plugins/basics.html#exports

int pluginHandle;
HWND hwndDlg;
int hMenu;
int hMenuDisasm;
int hMenuDump;
int hMenuStack;
int hMenuGraph;
int hMenuMemmap;
int hMenuSymmod;

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* initStruct)
{
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    pluginHandle = initStruct->pluginHandle;
    return pluginInit(initStruct);
}

PLUG_EXPORT bool plugstop()
{
    pluginStop();
    return true;
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE cb_type, PLUG_CB_MENUENTRY* info) {
    switch (info->hEntry)
    {
    case SEARCH_SIG:
    {
        char input[256] = { 0 };
        if (GuiGetLineWindow("Enter IDA sig", input)) {
            auto res = SearchSig(input);
            if (res) {
                char cmd[256]{};
                sprintf_s(cmd, "disasm %p", res); // 在反汇编窗口跳转
                DbgCmdExecDirect(cmd);
            } else {
                MessageBoxExA(hwndDlg , "error !!!!" , "title" , MB_OK | MB_ICONERROR, 0);
            }
        }
        break;
    }
    case CREATE_SIG:
    {
        dprintf("Sig: %s\n", CreateSig().c_str());
    }
    default:
        break;
    }
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setupStruct)
{
    hwndDlg = setupStruct->hwndDlg;
    hMenu = setupStruct->hMenu;
    hMenuDisasm = setupStruct->hMenuDisasm;
    hMenuDump = setupStruct->hMenuDump;
    hMenuStack = setupStruct->hMenuStack;
    hMenuGraph = setupStruct->hMenuGraph;
    hMenuMemmap = setupStruct->hMenuMemmap;
    hMenuSymmod = setupStruct->hMenuSymmod;
    pluginSetup();
}