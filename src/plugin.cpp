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

std::vector<std::uint8_t> _ReadModule(duint module) {
    IMAGE_DOS_HEADER dosHeader{};
    DbgMemRead(module, &dosHeader, sizeof(IMAGE_DOS_HEADER));
    IMAGE_NT_HEADERS ntHeaders{};
    DbgMemRead(module + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS));

    auto sizeOfImage = ntHeaders.OptionalHeader.SizeOfImage;
    std::vector<std::uint8_t> scanBytes(sizeOfImage);
    DbgMemRead(module, scanBytes.data(), sizeOfImage);
    return scanBytes;
}

std::uint8_t* PatternScan(duint base, std::vector<std::uint8_t> scanBytes, const char* signature)
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

    auto patternBytes = pattern_to_byte(signature);

    auto s = patternBytes.size();
    auto d = patternBytes.data();

    for (auto i = 0ul; i < scanBytes.size() - s; ++i) {
        bool found = true;
        for (auto j = 0ul; j < s; ++j) {
            if (scanBytes[i + j] != d[j] && d[j] != -1) {
                found = false;
                break;
            }
        }
        if (found) {
            return (std::uint8_t*)(base + i);
        }
    }
    return nullptr;
}

std::uint8_t* SearchSig(const char* sig)
{
    // TODO: Non ida sigs
    char modname[256] = { 0 };
    SELECTIONDATA sel;
    GuiSelectionGet(GUI_DISASSEMBLY, &sel);
    DbgGetModuleAt(sel.start, modname);
    auto base = DbgModBaseFromName(modname);
    dprintf("Searching for %s in %s (%p)\n", sig, modname, base);
    
    return PatternScan(base, _ReadModule(base), sig);
}

std::string getInstrHexWildCarded(ZydisDisassembledInstruction& instruction, const uint8_t* buffer, size_t length) {
    std::ostringstream hexStream;
    for (uint8_t i = 0; i < instruction.info.length; ++i)
    {
        bool isWildcard = false;
        for (uint8_t opIdx = 0; opIdx < instruction.info.operand_count; ++opIdx)
        {
            const auto& operand = instruction.operands[opIdx];
            if (operand.visibility != ZYDIS_OPERAND_VISIBILITY_EXPLICIT)
                continue;
            if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                if (i >= operand.imm.offset / 8 &&
                    i < (operand.imm.offset + operand.size) / 8)
                {
                    isWildcard = true;
                    break;
                }
            }

            if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (operand.mem.disp.size > 0)
                {
                    if (i >= operand.mem.disp.offset / 8 &&
                        i < (operand.mem.disp.offset + operand.mem.disp.size) / 8)
                    {
                        isWildcard = true;
                        break;
                    }
                }
            }
        }
        if (isWildcard)
            hexStream << "? ";
        else
            hexStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";

    }

    return hexStream.str();
}

std::string CreateSig()
{
    SELECTIONDATA sel;
    char modname[256] = { 0 };

    GuiSelectionGet(GUI_DISASSEMBLY, &sel);


    DbgGetModuleAt(sel.start, modname);
    auto base = DbgModBaseFromName(modname);

    auto moduleBuff = _ReadModule(base);

    auto addr = sel.start;

    int size = 14;

    std::vector<BYTE> instrBuff(size);

    while (true) {
        // TODO: I think its better to read from moduleBuff
        DbgMemRead(addr, instrBuff.data(), size);
        ZyanUSize offset = 0;
        ZydisDisassembledInstruction instruction;

        std::ostringstream res;

        auto currentAddr = addr;

        while (ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64, currentAddr, instrBuff.data() + offset, instrBuff.size() - offset, &instruction)))
        {
            res << getInstrHexWildCarded(instruction, instrBuff.data() + offset, instruction.info.length);
            offset += instruction.info.length;
            currentAddr += instruction.info.length;
            if (offset >= instrBuff.size())
                break;
        }

        std::string result = res.str();
        if (!result.empty() && result.back() == ' ')
            result.pop_back();
        if (PatternScan(base, moduleBuff, result.c_str()) == reinterpret_cast<std::uint8_t*>(sel.start))
            return result;
        size += 14;
        instrBuff.resize(size);
    }
    
}
