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
#include <map>
#include <thread>
#include <mutex>
#include <atomic>

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

static std::string WtoA(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(),
                                nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), (int)w.size(),
                        &s[0], n, nullptr, nullptr);
    return s;
}

static std::string ToLower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

static std::string Trim(std::string s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r'))
        s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.pop_back();
    return s;
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
    if (InetPtonW(AF_INET, dnsServer.c_str(), &v4) != 1) return false;
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

    if (pQueryResults) DnsRecordListFree(pQueryResults, DnsFreeRecordList);
    return ok;
}

static bool ResolveAllHosts(std::vector<HostMapping>& hosts,
                            const std::wstring& dnsServer,
                            std::wstring& errorOut)
{
    for (auto& h : hosts) {
        if (!h.ip.empty()) continue;
        if (dnsServer.empty()) {
            errorOut = L"host " + h.domain + L" 未提供 IP，且未指定 DNS";
            return false;
        }
        std::wstring ip;
        if (!ResolveViaDns(h.domain, dnsServer, ip)) {
            ip = L"127.0.0.1";
        }
        h.ip = std::move(ip);
    }
    return true;
}

class ScopedSocket {
public:
    ScopedSocket() = default;
    explicit ScopedSocket(SOCKET s) : s_(s) {}
    ~ScopedSocket() { reset(); }
    ScopedSocket(const ScopedSocket&) = delete;
    ScopedSocket& operator=(const ScopedSocket&) = delete;
    SOCKET get() const { return s_; }
    void reset(SOCKET s = INVALID_SOCKET) {
        if (s_ != INVALID_SOCKET) closesocket(s_);
        s_ = s;
    }
    bool valid() const { return s_ != INVALID_SOCKET; }
private:
    SOCKET s_ = INVALID_SOCKET;
};

class RedirectProxy {
public:
    RedirectProxy(const std::vector<HostMapping>& hosts, unsigned short targetPort = 80)
        : targetPort_(targetPort) {
        for (const auto& h : hosts) {
            if (h.domain.empty() || h.ip.empty()) continue;
            routes_[ToLower(WtoA(h.domain))] = WtoA(h.ip);
        }
    }
    ~RedirectProxy() { Stop(); }

    bool Start() {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
        wsaStarted_ = true;

        listen_.reset(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!listen_.valid()) return false;

        int opt = 1;
        setsockopt(listen_.get(), SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(0);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (bind(listen_.get(), (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) return false;
        if (listen(listen_.get(), SOMAXCONN) == SOCKET_ERROR) return false;

        int len = sizeof(addr);
        if (getsockname(listen_.get(), (sockaddr*)&addr, &len) == 0)
            port_ = ntohs(addr.sin_port);

        running_ = true;
        acceptThread_ = std::thread(&RedirectProxy::AcceptLoop, this);
        return true;
    }

    void Stop() {
        if (!running_.exchange(false)) {
            if (wsaStarted_) { WSACleanup(); wsaStarted_ = false; }
            return;
        }
        listen_.reset();
        if (acceptThread_.joinable()) acceptThread_.join();
        {
            std::lock_guard<std::mutex> lk(mu_);
            for (auto& t : workers_) if (t.joinable()) t.join();
            workers_.clear();
        }
        if (wsaStarted_) { WSACleanup(); wsaStarted_ = false; }
    }

    unsigned short Port() const { return port_; }

private:
    void AcceptLoop() {
        while (running_) {
            SOCKET c = accept(listen_.get(), nullptr, nullptr);
            if (c == INVALID_SOCKET) {
                if (!running_) break;
                continue;
            }
            std::lock_guard<std::mutex> lk(mu_);
            workers_.emplace_back(&RedirectProxy::HandleClient, this, c);
        }
    }

    static void Relay(SOCKET a, SOCKET b) {
        std::thread t1([a, b]() {
            char buf[16384];
            while (true) {
                int n = recv(a, buf, sizeof(buf), 0);
                if (n <= 0) break;
                int sent = 0;
                bool broken = false;
                while (sent < n) {
                    int w = send(b, buf + sent, n - sent, 0);
                    if (w == SOCKET_ERROR) { broken = true; break; }
                    sent += w;
                }
                if (broken) break;
            }
            shutdown(b, SD_SEND);
        });
        std::thread t2([a, b]() {
            char buf[16384];
            while (true) {
                int n = recv(b, buf, sizeof(buf), 0);
                if (n <= 0) break;
                int sent = 0;
                bool broken = false;
                while (sent < n) {
                    int w = send(a, buf + sent, n - sent, 0);
                    if (w == SOCKET_ERROR) { broken = true; break; }
                    sent += w;
                }
                if (broken) break;
            }
            shutdown(a, SD_SEND);
        });
        t1.join();
        t2.join();
    }

    void HandleClient(SOCKET rawClient) {
        ScopedSocket client(rawClient);

        DWORD timeout = 300000;
        setsockopt(client.get(), SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        std::string data;
        char buf[4096];
        while (data.find("\r\n\r\n") == std::string::npos) {
            int n = recv(client.get(), buf, sizeof(buf), 0);
            if (n <= 0) return;
            data.append(buf, n);
            if (data.size() > 64 * 1024) return;
        }

        size_t he = data.find("\r\n\r\n");
        std::string head = data.substr(0, he);
        std::string body = data.substr(he + 4);

        std::vector<std::string> lines;
        size_t start = 0;
        while (true) {
            size_t e = head.find("\r\n", start);
            if (e == std::string::npos) {
                lines.push_back(head.substr(start));
                break;
            }
            lines.push_back(head.substr(start, e - start));
            start = e + 2;
        }
        if (lines.empty()) return;

        const std::string& rl = lines[0];
        size_t s1 = rl.find(' ');
        if (s1 == std::string::npos) return;
        size_t s2 = rl.find(' ', s1 + 1);
        if (s2 == std::string::npos) return;

        std::string method  = rl.substr(0, s1);
        std::string url     = rl.substr(s1 + 1, s2 - s1 - 1);
        std::string version = rl.substr(s2 + 1);

        if (ToLower(method) == "connect") {
            std::string hostPort = url;
            std::string host = hostPort;
            std::string portStr = "443";
            auto colon = hostPort.rfind(':');
            if (colon != std::string::npos) {
                host    = hostPort.substr(0, colon);
                portStr = hostPort.substr(colon + 1);
            }
            host = ToLower(host);

            auto itc = routes_.find(host);
            if (itc == routes_.end()) {
                const char* r = "HTTP/1.1 403 Forbidden\r\n"
                                "Content-Length: 0\r\nConnection: close\r\n\r\n";
                send(client.get(), r, (int)strlen(r), 0);
                return;
            }

            unsigned short dstPort = (unsigned short)atoi(portStr.c_str());
            if (dstPort == 0) dstPort = 443;

            ScopedSocket target(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
            if (!target.valid()) return;

            sockaddr_in ta{};
            ta.sin_family = AF_INET;
            ta.sin_port   = htons(dstPort);
            if (InetPtonA(AF_INET, itc->second.c_str(), &ta.sin_addr) != 1) return;
            if (connect(target.get(), (sockaddr*)&ta, sizeof(ta)) == SOCKET_ERROR) {
                const char* r = "HTTP/1.1 502 Bad Gateway\r\n"
                                "Content-Length: 0\r\nConnection: close\r\n\r\n";
                send(client.get(), r, (int)strlen(r), 0);
                return;
            }

            const char* ok = "HTTP/1.1 200 Connection Established\r\n\r\n";
            send(client.get(), ok, (int)strlen(ok), 0);

            Relay(client.get(), target.get());
            return;
        }

        std::string hostHeader;
        for (size_t i = 1; i < lines.size(); ++i) {
            size_t c = lines[i].find(':');
            if (c == std::string::npos) continue;
            if (ToLower(lines[i].substr(0, c)) == "host") {
                hostHeader = Trim(lines[i].substr(c + 1));
                break;
            }
        }

        std::string hostOnly = hostHeader;
        {
            auto p = hostOnly.find(':');
            if (p != std::string::npos) hostOnly = hostOnly.substr(0, p);
        }
        hostOnly = ToLower(hostOnly);

        auto it = routes_.find(hostOnly);
        if (it == routes_.end()) {
            const char* r = "HTTP/1.1 403 Forbidden\r\n"
                            "Content-Length: 0\r\nConnection: close\r\n\r\n";
            send(client.get(), r, (int)strlen(r), 0);
            return;
        }

        std::string path = url;
        auto sp = path.find("://");
        if (sp != std::string::npos) {
            auto slash = path.find('/', sp + 3);
            if (slash == std::string::npos) path = "/";
            else path = path.substr(slash);
        }
        if (path.empty() || path[0] != '/') path = "/" + path;

        std::string newReq;
        newReq.reserve(data.size() + 64);
        newReq += method + " " + path + " " + version + "\r\n";
        for (size_t i = 1; i < lines.size(); ++i) {
            size_t c = lines[i].find(':');
            if (c != std::string::npos) {
                std::string k = ToLower(lines[i].substr(0, c));
                if (k == "connection" || k == "proxy-connection") continue;
            }
            newReq += lines[i] + "\r\n";
        }
        newReq += "Connection: close\r\n\r\n";
        newReq += body;

        ScopedSocket target(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
        if (!target.valid()) return;

        sockaddr_in ta{};
        ta.sin_family = AF_INET;
        ta.sin_port   = htons(targetPort_);
        if (InetPtonA(AF_INET, it->second.c_str(), &ta.sin_addr) != 1) return;
        if (connect(target.get(), (sockaddr*)&ta, sizeof(ta)) == SOCKET_ERROR) {
            const char* r = "HTTP/1.1 502 Bad Gateway\r\n"
                            "Content-Length: 0\r\nConnection: close\r\n\r\n";
            send(client.get(), r, (int)strlen(r), 0);
            return;
        }

        int sent = 0, total = (int)newReq.size();
        while (sent < total) {
            int w = send(target.get(), newReq.data() + sent, total - sent, 0);
            if (w == SOCKET_ERROR) return;
            sent += w;
        }

        Relay(client.get(), target.get());
    }

    std::map<std::string, std::string> routes_;
    ScopedSocket listen_;
    unsigned short targetPort_;
    unsigned short port_ = 0;
    std::atomic<bool> running_{ false };
    std::thread acceptThread_;
    std::vector<std::thread> workers_;
    std::mutex mu_;
    bool wsaStarted_ = false;
};

static std::wstring WritePacFile(const std::vector<HostMapping>& hosts,
                                 unsigned short proxyPort)
{
    std::string list;
    bool first = true;
    for (const auto& h : hosts) {
        if (h.domain.empty()) continue;
        if (!first) list += ",";
        first = false;
        list += "\"" + WtoA(h.domain) + "\"";
    }

    std::string pac =
        "function FindProxyForURL(url, host) {\n"
        "    host = host.toLowerCase();\n"
        "    var list = [" + list + "];\n"
        "    for (var i = 0; i < list.length; i++) {\n"
        "        if (host == list[i])\n"
        "            return \"PROXY 127.0.0.1:" + std::to_string(proxyPort) + "\";\n"
        "    }\n"
        "    return \"DIRECT\";\n"
        "}\n";

    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring path = std::wstring(tmp) + L"ocths_cealer_routes.pac";

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD written = 0;
    WriteFile(h, pac.c_str(), (DWORD)pac.size(), &written, nullptr);
    CloseHandle(h);
    return path;
}

int wmain(int, wchar_t**) {
    if (MessageBoxW(GetParentWindow(),
                    L"本程序将启动本地代理并重定向目标域名流量，\n仅用于您已被授权的合法网络环境下使用。\n\n继续使用即表示您已知悉并同意。",
                    L"免责声明", MB_YESNO | MB_ICONWARNING | MB_TASKMODAL | MB_DEFBUTTON1)
                    != IDYES) {
        return 0;
    }

    const std::wstring dnsServer = L"223.5.5.5";

    std::vector<HostMapping> hosts;
    hosts.push_back({ L"douyin.com", L"" });
    hosts.push_back({ L"www.douyin.com", L"" });
    hosts.push_back({ L"www-hj.douyin.com", L"" });
    hosts.push_back({ L"v.douyin.com", L"" });
    hosts.push_back({ L"live.douyin.com", L"" });
    hosts.push_back({ L"sso.douyin.com", L"" });
    hosts.push_back({ L"open.douyin.com", L"" });
    hosts.push_back({ L"api.douyin.com", L"" });
    hosts.push_back({ L"api-hl.douyin.com", L"" });
    hosts.push_back({ L"api.amemv.com", L"" });
    hosts.push_back({ L"aweme.snssdk.com", L"" });
    hosts.push_back({ L"log.snssdk.com", L"" });
    hosts.push_back({ L"mon.snssdk.com", L"" });
    hosts.push_back({ L"is.snssdk.com", L"" });
    hosts.push_back({ L"tnc3-bjlgy.zijieapi.com", L"" });
    hosts.push_back({ L"sf1-fe.tiktokv.com", L"" });
    hosts.push_back({ L"sf3-fe.tiktokv.com", L"" });
    hosts.push_back({ L"v26-web.douyinvod.com", L"" });
    hosts.push_back({ L"v3-web.douyinvod.com", L"" });
    hosts.push_back({ L"v9-web.douyinvod.com", L"" });
    hosts.push_back({ L"v26-web.douyinpic.com", L"" });
    hosts.push_back({ L"p3-sign.douyinpic.com", L"" });
    hosts.push_back({ L"p9-sign.douyinpic.com", L"" });
    hosts.push_back({ L"p26-sign.douyinpic.com", L"" });
    hosts.push_back({ L"p11-sign.douyinpic.com", L"" });

    hosts.push_back({ L"mihoyo.com", L"" });
    hosts.push_back({ L"www.mihoyo.com", L"" });
    hosts.push_back({ L"user.mihoyo.com", L"" });
    hosts.push_back({ L"account.mihoyo.com", L"" });
    hosts.push_back({ L"bbs.mihoyo.com", L"" });
    hosts.push_back({ L"ys.mihoyo.com", L"" });
    hosts.push_back({ L"genshin.mihoyo.com", L"" });
    hosts.push_back({ L"zzz.mihoyo.com", L"" });
    hosts.push_back({ L"honkaiimpact3.mihoyo.com", L"" });
    hosts.push_back({ L"bh3.mihoyo.com", L"" });
    hosts.push_back({ L"wd.mihoyo.com", L"" });
    hosts.push_back({ L"mhyy.mihoyo.com", L"" });
    hosts.push_back({ L"webstatic.mihoyo.com", L"" });
    hosts.push_back({ L"sdk-static.mihoyo.com", L"" });
    hosts.push_back({ L"api-static.mihoyo.com", L"" });
    hosts.push_back({ L"api-takumi.mihoyo.com", L"" });
    hosts.push_back({ L"api-os-takumi.mihoyo.com", L"" });
    hosts.push_back({ L"hk4e-sdk-s.mihoyo.com", L"" });
    hosts.push_back({ L"log-upload.mihoyo.com", L"" });
    hosts.push_back({ L"public-data-api.mihoyo.com", L"" });
    hosts.push_back({ L"minor-api.mihoyo.com", L"" });
    hosts.push_back({ L"api-takumi-static.mihoyo.com", L"" });
    hosts.push_back({ L"act.mihoyo.com", L"" });
    hosts.push_back({ L"upload-static.mihoyo.com", L"" });
    hosts.push_back({ L"hk4e-api.mihoyo.com", L"" });
    hosts.push_back({ L"hk4e-api-os.mihoyo.com", L"" });
    hosts.push_back({ L"hk4e-sdk.mihoyo.com", L"" });
    hosts.push_back({ L"hk4e-sdk-os.mihoyo.com", L"" });
    hosts.push_back({ L"hyp-api.mihoyo.com", L"" });
    hosts.push_back({ L"jhyapi.mihoyo.com", L"" });
    hosts.push_back({ L"passport-api.mihoyo.com", L"" });
    hosts.push_back({ L"api-cloudgame.mihoyo.com", L"" });
    hosts.push_back({ L"cg-hk4e-api.mihoyo.com", L"" });
    hosts.push_back({ L"cg-hk4e-sdk.mihoyo.com", L"" });
    hosts.push_back({ L"devops-api.mihoyo.com", L"" });
    hosts.push_back({ L"announcement-api.mihoyo.com", L"" });
    hosts.push_back({ L"hk4e-announcement-api.mihoyo.com", L"" });
    hosts.push_back({ L"hk4e-sdk-static.mihoyo.com", L"" });
    hosts.push_back({ L"hk4e-static.mihoyo.com", L"" });

    std::wstring err;
    if (!ResolveAllHosts(hosts, dnsServer, err)) {
        ShowError(err);
        return 1;
    }

    RedirectProxy proxy(hosts, 80);
    if (!proxy.Start()) {
        ShowError(L"本地代理启动失败。");
        return 1;
    }

    std::wstring pacPath = WritePacFile(hosts, proxy.Port());
    if (pacPath.empty()) {
        ShowError(L"PAC 文件写入失败。");
        proxy.Stop();
        return 1;
    }

    std::wstring pacUrl = L"file:///";
    for (wchar_t c : pacPath) pacUrl += (c == L'\\') ? L'/' : c;

    std::wstring browser = GetDefaultBrowserPath();
    if (browser.empty()) {
        ShowError(L"无法获取默认浏览器路径。");
        proxy.Stop();
        return 1;
    }

    std::vector<std::wstring> args;
    args.push_back(browser);
    args.push_back(L"--proxy-pac-url=" + pacUrl);
    args.push_back(L"--user-data-dir=C:\\Temp\\OCTHS-Cealer");

    std::wstring cmdLine;
    for (size_t i = 0; i < args.size(); ++i) {
        if (i) cmdLine.push_back(L' ');
        cmdLine += QuoteArg(args[i]);
    }

    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(L'\0');

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessW(NULL, buf.data(), NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        ShowError(L"CreateProcessW 失败，错误码: " +
                  std::to_wstring(GetLastError()));
        proxy.Stop();
        return 1;
    }

    CloseHandle(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    proxy.Stop();

    MessageBoxW(GetParentWindow(),
                L"Ceal this fxxking shit.\n\nSee more on https://github.com/chen-linkai/ocths-cealer.",
                L"clk PRESENT", MB_OK | MB_ICONINFORMATION | MB_DEFBUTTON1);
    return 0;
}