// Copyright (c) 2026 CR1M (https://cr1m.net | support@cr1m.net)
// Licensed under CR1M Source Available License v1.0 (see LICENSE).
// Redistribution of compiled binaries or modified forks is strictly prohibited.

#pragma once

#include "cr1m/build_config.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace cr1m {

void WipeStr(std::string& s);
void WipeWStr(std::wstring& s);

std::string  StripWhitespace(const std::string& s);
std::string  Trim(const std::string& s);
std::string  ToUpperAscii(std::string s);
std::string  WideToUtf8(const std::wstring& w);
std::wstring Utf8ToWide(const std::string& s);
std::string  JsonEscape(const std::string& s);
std::string  GetEnvVarUtf8(const std::string& name);

void CreateDirW(const std::wstring& dir);
bool ReadFileUtf8W(const std::wstring& path, std::string& out);
bool WriteFileUtf8W(const std::wstring& path, const std::string& data);
bool ReadFileBytes(const std::string& path, std::vector<uint8_t>& out, bool& exists);
void WriteFileBytesHidden(const std::string& dir, const std::string& path, const void* data, size_t len);
bool SaveLicenseKeyAtomic(const std::string& licDir, const std::string& licPath, const std::string& content);

std::string CleanKeyPaste(const std::string& raw);
std::string GetAppDataBaseDir();
std::string GetLocalAppDataDirA();
std::string GetProgramDataBaseDir();
std::string GetPublicDocsDirA();

void ShredAndDeleteFileW(const std::wstring& path);
void PurgeLegacyDebugLogs();
void SetColor(WORD attr);

std::string BytesToLowerHex(const BYTE* b, size_t n);
std::string BytesToUpperHex(const BYTE* b, size_t n);
bool        HexDecode(const std::string& hex, std::vector<BYTE>& out);
bool        CtEqualStr(const std::string& a, const std::string& b);

bool        IsValidLicenseKeyChar(char c);
bool        IsValidLicenseKeyFormat(const std::string& key);
std::string NormalizeLicenseKeyPaste(const std::string& raw);
std::string MaskLicenseKeyForDisplay(const std::string& key);

bool JsonFindValueStart(const std::string& json, const std::string& key, size_t& outPos);
bool JsonExtractStringField(const std::string& json, const std::string& key, std::string& outVal);
bool JsonExtractBoolField(const std::string& json, const std::string& key, bool& outVal);

} // namespace cr1m
