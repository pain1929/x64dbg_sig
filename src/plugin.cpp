#include "plugin.h"

// Examples: https://github.com/x64dbg/x64dbg/wiki/Plugins
// References:
// - https://help.x64dbg.com/en/latest/developers/plugins/index.html
// - https://x64dbg.com/blog/2016/10/04/architecture-of-x64dbg.html
// - https://x64dbg.com/blog/2016/10/20/threading-model.html
// - https://x64dbg.com/blog/2016/07/30/x64dbg-plugin-sdk.html

// Command use the same signature as main in C
// argv[0] contains the full command, after that are the arguments
// NOTE: arguments are separated by a COMMA (not space like WinDbg)

// Initialize your plugin data here.
bool pluginInit(PLUG_INITSTRUCT* initStruct)
{
    dprintf("pluginInit(pluginHandle: %d)\n", pluginHandle);

    // Prefix of the functions to call here: _plugin_register
    //_plugin_registercommand(pluginHandle, PLUGIN_NAME, cbExampleCommand, true);
    // Return false to cancel loading the plugin.
    return true;
}

// Deinitialize your plugin data here.
// NOTE: you are responsible for gracefully closing your GUI
// This function is not executed on the GUI thread, so you might need
// to use WaitForSingleObject or similar to wait for everything to close.
void pluginStop()
{
    // Prefix of the functions to call here: _plugin_unregister

    dprintf("pluginStop(pluginHandle: %d)\n", pluginHandle);
}

// Do GUI/Menu related things here.
// This code runs on the GUI thread: GetCurrentThreadId() == GuiGetMainThreadId()
// You can get the HWND using GuiGetWindowHandle()
void pluginSetup()
{
    // Prefix of the functions to call here: _plugin_menu
    _plugin_menuaddentry(hMenuDisasm, SEARCH_SIG, "Sig Search");
    _plugin_menuaddentry(hMenuDisasm, CREATE_SIG, "Sig Create");
    dprintf("pluginSetup(pluginHandle: %d)\n", pluginHandle);
}

std::uint8_t* PatternScan(duint module, const char* signature)
{
    static auto pattern_to_byte = [](const char* pattern) {
        auto bytes = std::vector<int>{};
        auto start = const_cast<char*>(pattern);
        auto end = const_cast<char*>(pattern) + strlen(pattern);

        for (auto current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?')
                    ++current;
                bytes.push_back(-1);
            }
            else {
                bytes.push_back(strtoul(current, &current, 16));
            }
        }
        return bytes;
        };
    IMAGE_DOS_HEADER dosHeader{};
    DbgMemRead(module, &dosHeader, sizeof(IMAGE_DOS_HEADER));
    IMAGE_NT_HEADERS ntHeaders{};
    
    DbgMemRead(module + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS));

    auto sizeOfImage = ntHeaders.OptionalHeader.SizeOfImage;
    //dprintf("SIZE: %d\n", sizeOfImage);
    auto patternBytes = pattern_to_byte(signature);

    std::vector<std::uint8_t> scanBytes(sizeOfImage);
    DbgMemRead(module, scanBytes.data(), sizeOfImage);
    //auto scanBytes = (module);

    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < sizeOfImage - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            //BYTE shit;
            //DbgMemRead(scanBytes+i+j, &shit, sizeof(BYTE));
            //if (shit != d[j] && d[j] != (BYTE)-1) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return (std::uint8_t*)(module + i);
        }
    }
    return nullptr;
}

std::uint8_t* SearchSig(const char* sig)
{
    char modname[256] = { 0 };
    SELECTIONDATA sel;
    GuiSelectionGet(GUI_DISASSEMBLY, &sel);
    DbgGetModuleAt(sel.start, modname);
    auto base = DbgModBaseFromName(modname);
    dprintf("Searching for %s in %s (%p)\n", sig, modname, base);
    
    return PatternScan(base, sig);
}

std::string CreateSig()
{
    return "TODO";
}
