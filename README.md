# Sigarette

Functions:

- Create ida sig
- Search for ida sig

## Building

From a Visual Studio command prompt:

```
cmake -B build64 -A x64
cmake --build build64 --config Release
```

You will get `build64\PluginTemplate.sln` that you can open in Visual Studio.

To build a 32-bit plugin:

```
cmake -B build32 -A Win32
cmake --build build32 --config Release
```

Alternatively you can open this folder in Visual Studio/CLion/Qt Creator.