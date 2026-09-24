#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <iphlpapi.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <cstdlib>
#include <string>
#include <vector>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/ENTRY:wmainCRTStartup")

struct HostMapping {
    std::wstring domain;
    std::wstring ip;
};

struct LaunchOptions {
    std::vector<HostMapping> hosts;
    std::wstring startUrl;
    std::wstring userDataDir = L"C:\\Temp\\OCTHS-Cealer";
    std::wstring browserPath;
    std::wstring extraFlags;
    std::wstring dnsServer;
};

enum class LaunchResult { Success, Failed };

static HWND GetParentWindow() { return GetConsoleWindow(); }

static void ShowError(const std::wstring& msg) {
    MessageBoxW(GetParentWindow(), msg.c_str(), L"错误",
                MB_OK | MB_ICONERROR | MB_TASKMODAL);
}

static std::wstring QuoteArg(const std::wstring& arg) {
    if (arg.empty()) return L"\"\"";
    if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;

    std::wstring out;
    out.push_back(L'"');
    size_t backslashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') {
            ++backslashes;
        } else if (c == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
            backslashes = 0;
        } else {
            out.append(backslashes, L'\\');
            backslashes = 0;
            out.push_back(c);
        }
    }
    out.append(backslashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

static std::wstring BuildResolverRules(const std::vector<HostMapping>& hosts) {
    std::wstring rules;
    bool first = true;
    for (const auto& h : hosts) {
        if (h.domain.empty() || h.ip.empty()) continue;
        if (!first) rules += L", ";
        first = false;
        rules += L"MAP " + h.domain + L" " + h.ip;
    }
    return rules;
}

static std::wstring GetDefaultBrowserPath() {
    DWORD size = 0;
    AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE,
                      L"http", L"open", nullptr, &size);
    if (size == 0) return {};

    std::wstring buffer(size, L'\0');
    HRESULT hr = AssocQueryStringW(ASSOCF_NONE, ASSOCSTR_EXECUTABLE,
                                   L"http", L"open", &buffer[0], &size);
    if (FAILED(hr)) return {};
    return std::wstring(buffer.c_str());
}

static bool ResolveViaDns(const std::wstring& host,
                          const std::wstring& dnsServer,
                          std::wstring& outIp)
{
    IP4_ARRAY* pIp4Array = static_cast<IP4_ARRAY*>(malloc(sizeof(IP4_ARRAY)));
    if (!pIp4Array) return false;

    struct FreeGuard {
        IP4_ARRAY* p;
        ~FreeGuard() { if (p) free(p); }
    } guard{ pIp4Array };

    ZeroMemory(pIp4Array, sizeof(IP4_ARRAY));
    pIp4Array->AddrCount = 1;

    IN_ADDR v4 = {};
    if (InetPtonW(AF_INET, dnsServer.c_str(), &v4) != 1) {
        return false;
    }
    pIp4Array->AddrArray[0] = v4.S_un.S_addr;

    PDNS_RECORD pQueryResults = nullptr;
    DNS_STATUS status = DnsQuery_W(
        host.c_str(),
        DNS_TYPE_A,
        DNS_QUERY_BYPASS_CACHE | DNS_QUERY_STANDARD,
        pIp4Array,
        &pQueryResults,
        nullptr
    );

    bool ok = false;
    if (status == ERROR_SUCCESS && pQueryResults) {
        for (DNS_RECORD* rec = pQueryResults; rec; rec = rec->pNext) {
            if (rec->wType == DNS_TYPE_A) {
                IN_ADDR a;
                a.S_un.S_addr = rec->Data.A.IpAddress;
                wchar_t buf[INET_ADDRSTRLEN] = {};
                if (InetNtopW(AF_INET, &a, buf, INET_ADDRSTRLEN)) {
                    outIp = buf;
                    ok = true;
                }
                break;
            }
        }
    }

    if (pQueryResults) {
        DnsRecordListFree(pQueryResults, DnsFreeRecordList);
    }
    return ok;
}

static bool ResolveAllHosts(std::vector<HostMapping>& hosts,
                            const std::wstring& dnsServer,
                            std::wstring& errorOut)
{
    for (auto& h : hosts) {
        if (!h.ip.empty()) continue;

        if (dnsServer.empty()) {
            errorOut = L"host " + h.domain +
                       L" 未提供 IP，且未指定 --dns=服务器";
            return false;
        }

        std::wstring ip;
        if (!ResolveViaDns(h.domain, dnsServer, ip)) {
            errorOut = L"无法通过 " + dnsServer + L" 解析 " + h.domain;
            return false;
        }
        h.ip = std::move(ip);
    }
    return true;
}

static LaunchResult LaunchBrowser(const LaunchOptions& opts) {
    std::wstring browserPath = opts.browserPath.empty()
        ? GetDefaultBrowserPath()
        : opts.browserPath;

    if (browserPath.empty()) {
        ShowError(L"无法获取默认浏览器路径。");
        return LaunchResult::Failed;
    }

    std::vector<std::wstring> args;
    args.push_back(browserPath);

    const std::wstring resolverRules = BuildResolverRules(opts.hosts);
    if (!resolverRules.empty()) {
        args.push_back(L"--host-resolver-rules=" + resolverRules);
    }

    if (!opts.userDataDir.empty()) {
        args.push_back(L"--user-data-dir=" + opts.userDataDir);
    }

    if (!opts.extraFlags.empty()) {
        int argc = 0;
        LPWSTR* argv = CommandLineToArgvW(opts.extraFlags.c_str(), &argc);
        if (argv) {
            for (int i = 0; i < argc; ++i) args.emplace_back(argv[i]);
            LocalFree(argv);
        }
    }

    if (!opts.startUrl.empty()) args.push_back(opts.startUrl);

    std::wstring cmdLine;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) cmdLine.push_back(L' ');
        cmdLine += QuoteArg(args[i]);
    }

    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    BOOL ok = CreateProcessW(NULL, buf.data(), NULL, NULL, FALSE,
                             0, NULL, NULL, &si, &pi);
    if (!ok) {
        ShowError(L"CreateProcessW 失败，错误码: " +
                  std::to_wstring(GetLastError()));
        return LaunchResult::Failed;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return LaunchResult::Success;
}

int wmain(int, wchar_t**) {
    if (MessageBoxW(GetParentWindow(), 
                    L"本程序将修改网络设置并启动浏览器以设置目标域名地址，\n仅用于您已被授权的合法网络环境下使用。\n\n继续使用即表示您已知悉并同意。",
                    L"免责声明", MB_YESNO | MB_ICONWARNING | MB_TASKMODAL | MB_DEFBUTTON1)
                    != IDYES) {
        return 0;
    }

    LaunchOptions opts;
    const std::wstring dnsServer = L"223.5.5.5";

    if (opts.hosts.empty()) {
        opts.hosts.push_back({ L"douyin.com", L"" });
        opts.hosts.push_back({ L"www.douyin.com", L"" });
        opts.hosts.push_back({ L"www-hj.douyin.com", L"" });
        opts.hosts.push_back({ L"v.douyin.com", L"" });
        opts.hosts.push_back({ L"live.douyin.com", L"" });
        opts.hosts.push_back({ L"sso.douyin.com", L"" });
        opts.hosts.push_back({ L"open.douyin.com", L"" });

        opts.hosts.push_back({ L"mihoyo.com", L"" });
        opts.hosts.push_back({ L"www.mihoyo.com", L"" });
        opts.hosts.push_back({ L"user.mihoyo.com", L"" });
        opts.hosts.push_back({ L"account.mihoyo.com", L"" });
        opts.hosts.push_back({ L"bbs.mihoyo.com", L"" });
        opts.hosts.push_back({ L"ys.mihoyo.com", L"" });
        opts.hosts.push_back({ L"genshin.mihoyo.com", L"" });
        opts.hosts.push_back({ L"zzz.mihoyo.com", L"" });
        opts.hosts.push_back({ L"honkaiimpact3.mihoyo.com", L"" });
        opts.hosts.push_back({ L"bh3.mihoyo.com", L"" });
        opts.hosts.push_back({ L"wd.mihoyo.com", L"" });
        opts.hosts.push_back({ L"mhyy.mihoyo.com", L"" });
        opts.hosts.push_back({ L"webstatic.mihoyo.com", L"" });
        opts.hosts.push_back({ L"sdk-static.mihoyo.com", L"" });
        opts.hosts.push_back({ L"api-static.mihoyo.com", L"" });
        opts.hosts.push_back({ L"api-takumi.mihoyo.com", L"" });
        opts.hosts.push_back({ L"api-os-takumi.mihoyo.com", L"" });
        opts.hosts.push_back({ L"hk4e-sdk-s.mihoyo.com", L"" });
        opts.hosts.push_back({ L"log-upload.mihoyo.com", L"" });
        opts.hosts.push_back({ L"public-data-api.mihoyo.com", L"" });
        opts.hosts.push_back({ L"minor-api.mihoyo.com", L"" });
    }

    std::wstring err;
    if (!ResolveAllHosts(opts.hosts, dnsServer, err)) {
        ShowError(err);
        return 1;
    }

    switch (LaunchBrowser(opts)) {
    case LaunchResult::Success: {
        MessageBoxW(GetParentWindow(), 
                    L"Ceal this fxxking shit.\n\nSee more on https://github.com/chen-linkai/ocths-cealer.",
                    L"clk PRESENT", MB_OK | MB_ICONINFORMATION | MB_DEFBUTTON1);
        return 0;
    }
    case LaunchResult::Failed:    return 1;
    }
    return 1;
}
