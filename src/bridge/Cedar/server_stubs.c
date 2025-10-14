// Server Stubs - Comprehensive stub implementations for VPN_CLIENT_ONLY builds
// These functions are called by client code but implement server-side features.
// All functions disabled when VPN_CLIENT_ONLY flag is set during compilation.

// ============================================================================
// VPN_CLIENT_ONLY: Only compile stubs when server code is wrapped
// These stubs replace wrapped server functions (SecureNAT, Bridge, NAT, IPsec, etc.)
// ============================================================================
#ifdef VPN_CLIENT_ONLY

#include "../Mayaqua/Mayaqua.h"
#include "../Mayaqua/Microsoft.h"
#include "../Mayaqua/Network.h"
#include "../Mayaqua/Object.h"
#include "CedarType.h"

// Forward declarations for types not in CedarType.h
typedef struct CEDAR CEDAR;
typedef struct PACK PACK;
typedef struct IPC IPC;
typedef struct IPC_PARAM IPC_PARAM;
typedef struct ETH ETH;
typedef struct LOCALBRIDGE LOCALBRIDGE;
typedef struct IPSEC_SERVER IPSEC_SERVER;
typedef struct IPSEC_SERVICES IPSEC_SERVICES;
typedef struct OPENVPN_SERVER_UDP OPENVPN_SERVER_UDP;
typedef struct VH_OPTION VH_OPTION;
typedef struct NAT NAT;
typedef struct DHCP_LEASE DHCP_LEASE;
typedef struct RPC_ENUM_DHCP RPC_ENUM_DHCP;
typedef struct RPC_ENUM_NAT RPC_ENUM_NAT;
typedef struct RPC_NAT_STATUS RPC_NAT_STATUS;
typedef PACK *(RPC_DISPATCHER)(RPC *r, char *function_name, PACK *p);
typedef struct WU_WEBUI_st WU_WEBUI;
typedef struct WU_WEBPAGE_st WU_WEBPAGE;

// ============================================================================
// Global Variables (defined in wrapped server files)
// ============================================================================

UINT vpn_global_parameters[128] = {0};

// ============================================================================
// RPC Stubs
// ============================================================================

RPC *StartRpcClient(SOCK *s, void *param) {
    return NULL;
}

RPC *StartRpcServer(SOCK *s, RPC_DISPATCHER *d, void *param) {
    return NULL;
}

bool ServerDownloadSignature(CONNECTION *c, char **error_detail_str) {
    return false;
}

// ============================================================================
// Remote.c Stubs - RPC utility functions
// ============================================================================

void EndRpc(RPC *rpc) {
    // No-op: Client doesn't use RPC
}

PACK *RpcCall(RPC *rpc, char *function_name, PACK *p) {
    return NULL; // Client doesn't make RPC calls
}

bool RpcError(PACK *p) {
    return true; // Always error for client
}

void RpcFree(RPC *rpc) {
    // No-op: Client doesn't free RPC
}

UINT RpcGetError(PACK *p) {
    return 1; // Generic error
}

bool RpcIsOk(PACK *p) {
    return false; // Always false for client
}

RPC *RpcServer(SOCK *s, RPC_DISPATCHER *dispatch, void *param) {
    return NULL; // Client doesn't create RPC servers
}

// ============================================================================
// Sam.c Stubs - User authentication (server-side)
// Client doesn't verify passwords, server does
// ============================================================================

bool SamAuthUserByAnonymous(void *hub, char *username) {
    return false; // Client doesn't authenticate users
}

bool SamAuthUserByCert(void *hub, char *username, void *cert) {
    return false; // Client doesn't authenticate by certificate
}

bool SamAuthUserByPassword(void *hub, char *username, void *random, void *secure_password, 
                           bool *is_radius_login, void *mschap, void *eap_client) {
    return false; // Client doesn't authenticate by password
}

bool SamAuthUserByPlainPassword(void *connection, void *hub, char *username, char *password,
                                 bool ast, void *mschap_v2_server_response_20, void *radius_login_opt) {
    return false; // Client doesn't authenticate by plain password
}

void *SamGetUserPolicy(void *hub, char *username) {
    return NULL; // Client doesn't get user policies
}

void SecurePassword(void *secure_password, void *password, void *random) {
    // No-op: Client doesn't secure passwords (server does)
}

void *GetIssuerFromList(void *cert_list) {
    return NULL; // Client doesn't get issuers
}

// ============================================================================
// Hub Management Stubs
// ============================================================================

void StopHub(HUB *h) {
    // Server-only
}

void UnlockHubList(CEDAR *c) {
    // Server-only
}

// ============================================================================
// Listener Stubs
// ============================================================================

void StopListener(LISTENER *r) {
    // Server-only
}

// ============================================================================
// WebUI Stubs
// ============================================================================

WU_WEBUI *WuNewWebUI(CEDAR *cedar) {
    return NULL;
}

void WuFreeWebUI(WU_WEBUI *wu) {
}

WU_WEBPAGE *WuGetPage(WU_WEBUI *wu, char *path) {
    return NULL;
}

void WuFreeWebPage(WU_WEBPAGE *page) {
}

// ============================================================================
// Ethernet Bridge Stubs (Bridge.c, BridgeUnix.c)
// ============================================================================

ETH *OpenEth(char *name, bool local, bool tapmode, char *tapaddr) {
    return NULL;
}

void CloseEth(ETH *e) {
}

void FreeEth(ETH *e) {
}

CANCEL *EthGetCancel(ETH *e) {
    return NULL;
}

UINT EthGetMtu(ETH *e) {
    return 1500;
}

bool EthSetMtu(ETH *e, UINT mtu) {
    return false;
}

bool EthIsChangeMtuSupported(ETH *e) {
    return false;
}

UINT EthGetPacket(ETH *e, void **data) {
    return 0;
}

void EthPutPackets(ETH *e, UINT num, void **datas, UINT *sizes) {
}

bool IsEthSupported() {
    return false;
}

bool IsEthInterfaceDescriptionSupportedUnix() {
    return false;
}

char *EthGetInterfaceDescriptionUnix(char *name) {
    return NULL;
}

bool IsBridgeSupported() {
    return false;
}

bool IsNeedWinPcap() {
    return false;
}

TOKEN_LIST *GetEthList() {
    TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));
    return t;
}

TOKEN_LIST *GetEthListEx(UINT *total_num_including_hidden, bool enum_normal, bool enum_rawip) {
    if (total_num_including_hidden != NULL) {
        *total_num_including_hidden = 0;
    }
    TOKEN_LIST *t = ZeroMalloc(sizeof(TOKEN_LIST));
    return t;
}

UINT GetEthDeviceHash() {
    return 0;
}

// ============================================================================
// Local Bridge Stubs (Bridge.c)
// ============================================================================

void InitLocalBridgeList(CEDAR *cedar) {
}

void FreeLocalBridgeList(CEDAR *cedar) {
}

bool AddLocalBridge(CEDAR *cedar, char *hubname, char *devicename, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast) {
    return false;
}

bool DeleteLocalBridge(CEDAR *cedar, char *hubname, char *devicename) {
    return false;
}

UINT BrNewBridge(HUB *h, char *name, POLICY *p, bool local, bool monitor, bool tapmode, char *tapaddr, bool limit_broadcast, BRIDGE **bridge) {
    if (bridge != NULL) {
        *bridge = NULL;
    }
    return 0;
}

void BrFreeBridge(BRIDGE *b) {
}

// ============================================================================
// SecureNAT Stubs (SecureNAT.c)
// ============================================================================

SNAT *SnNewSecureNAT(HUB *h, VH_OPTION *o) {
    return NULL;
}

void SnFreeSecureNAT(SNAT *s) {
}

// ============================================================================
// NAT Stubs (Nat.c)
// ============================================================================

void NtEnumNatList(NAT *n, RPC_ENUM_NAT *t) {
}

void NtEnumDhcpList(NAT *n, RPC_ENUM_DHCP *t) {
}

void NtGetStatus(NAT *n, RPC_NAT_STATUS *t) {
}

void FreeRpcEnumNat(RPC_ENUM_NAT *t) {
}

void FreeRpcEnumDhcp(RPC_ENUM_DHCP *t) {
}

void FreeRpcNatStatus(RPC_NAT_STATUS *t) {
}

void InRpcEnumNat(RPC_ENUM_NAT *t, PACK *p) {
}

void OutRpcEnumNat(PACK *p, RPC_ENUM_NAT *t) {
}

void InRpcEnumDhcp(RPC_ENUM_DHCP *t, PACK *p) {
}

void OutRpcEnumDhcp(PACK *p, RPC_ENUM_DHCP *t) {
}

void InRpcNatStatus(RPC_NAT_STATUS *t, PACK *p) {
}

void OutRpcNatStatus(PACK *p, RPC_NAT_STATUS *t) {
}

// ============================================================================
// Virtual Host Option Stubs (SecureNAT.c)
// ============================================================================

void NiSetDefaultVhOption(VH_OPTION *o) {
}

void NiLoadVhOptionEx(VH_OPTION *o, FOLDER *root) {
}

void NiWriteVhOptionEx(VH_OPTION *o, FOLDER *root) {
}

void NiClearUnsupportedVhOptionForDynamicHub(VH_OPTION *o, bool initial) {
}

void InVhOption(VH_OPTION *t, PACK *p) {
}

void OutVhOption(PACK *p, VH_OPTION *t) {
}

// ============================================================================
// IPC (IPsec Virtual Network Adapter) Stubs (IPsec_IPC.c)
// ============================================================================

IPC *NewIPCByParam(CEDAR *cedar, IPC_PARAM *param, UINT *error_code) {
    if (error_code != NULL) {
        *error_code = 1;
    }
    return NULL;
}

IPC *NewIPCBySock(CEDAR *cedar, SOCK *s, void *mac_address) {
    return NULL;
}

void FreeIPC(IPC *ipc) {
}

bool IsIPCConnected(IPC *ipc) {
    return false;
}

void IPCSetSockEventWhenRecvL2Packet(IPC *ipc, SOCK_EVENT *e) {
}

void IPCRecvL2(IPC *ipc) {
}

void IPCSendL2(IPC *ipc, UCHAR *data, UINT size) {
}

void IPCRecvIPv4(IPC *ipc) {
}

void IPCSendIPv4(IPC *ipc, void *data, UINT size) {
}

void IPCSetIPv4Parameters(IPC *ipc, IP *ip, IP *subnet, IP *gw, DHCP_CLASSLESS_ROUTE_TABLE *route_table) {
}

UINT IPCDhcpAllocateIP(IPC *ipc, DHCP_OPTION_LIST *req, IP *dest_ip, IP *dest_mask, IP *dest_gateway, DHCP_CLASSLESS_ROUTE_TABLE *dest_classless_route) {
    return 0;
}

bool IPCDhcpRenewIP(IPC *ipc, IP *dest_ip, IP *dest_gateway) {
    return false;
}

void IPCDhcpFreeIP(IPC *ipc, IP *ip) {
}

void IPCFlushArpTable(IPC *ipc) {
}

void IPCProcessInterrupts(IPC *ipc) {
}

void IPCProcessL3Events(IPC *ipc) {
}

// ============================================================================
// IPsec Server Stubs (IPsec.c)
// ============================================================================

IPSEC_SERVER *NewIPsecServer(CEDAR *cedar, IPSEC_SERVICES *services) {
    return NULL;
}

void FreeIPsecServer(IPSEC_SERVER *s) {
}

void IPsecServerSetServices(IPSEC_SERVER *s, IPSEC_SERVICES *services) {
}

void IPsecServerGetServices(IPSEC_SERVER *s, IPSEC_SERVICES *services) {
}

UINT SearchEtherIPId(IPSEC_SERVER *s, char *id) {
    return 0;
}

void AddEtherIPId(IPSEC_SERVER *s, char *id) {
}

void DeleteEtherIPId(IPSEC_SERVER *s, char *id) {
}

// ============================================================================
// OpenVPN/SSTP Server Stubs (Interop_OpenVPN.c, Interop_SSTP.c)
// ============================================================================

OPENVPN_SERVER_UDP *NewOpenVpnServerUdp(CEDAR *cedar) {
    return NULL;
}

void FreeOpenVpnServerUdp(OPENVPN_SERVER_UDP *u) {
}

void OvsApplyUdpPortList(OPENVPN_SERVER_UDP *u, char *port_list) {
}

bool OvsCheckTcpRecvBufIfOpenVPNProtocol(UCHAR *buf, UINT size) {
    return false;
}

void OvsPerformTcpServer(CEDAR *cedar, SOCK *sock) {
}

bool OvsGetNoOpenVpnTcp() {
    return true;
}

void AcceptSstp(CONNECTION *c) {
}

bool GetNoSstp() {
    return true;
}

// ============================================================================
// MS-CHAPv2 Authentication Stubs (Sam.c)
// ============================================================================

bool ParseAndExtractMsChapV2InfoFromPassword(IPC_MSCHAP_V2_AUTHINFO *d, char *password) {
    return false;
}

void MsChapV2DoBruteForce(IPC_MSCHAP_V2_AUTHINFO *d, LIST *password_list) {
}

void GenerateChallenge8(UCHAR *c) {
}

void GenerateNtPasswordHashHash(UCHAR *dst_hash, UCHAR *src_hash) {
}

void GenerateResponse(UCHAR *response, UCHAR *challenge8, UCHAR *nt_password_hash_hash) {
}

// ============================================================================
// MAC Address Validation Stub
// ============================================================================

bool IsValidUnicastMacAddress(UCHAR *mac) {
    if (mac == NULL) {
        return false;
    }
    // Basic validation: not all zeros, not multicast
    if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0) {
        return false;
    }
    if ((mac[0] & 0x01) != 0) {
        return false;
    }
    return true;
}

// ============================================================================
// Additional Missing Stubs
// ============================================================================

// Ethernet initialization (Bridge.c/BridgeUnix.c)
void InitEth() {
}

bool EthIsInterfaceDescriptionSupportedUnix() {
    return false;
}

// MS-CHAPv2 functions (Sam.c) - proper names
void MsChapV2_GenerateChallenge8(UCHAR *c) {
    if (c != NULL) {
        memset(c, 0, 8);
    }
}

void MsChapV2Server_GenerateResponse(UCHAR *response, UCHAR *challenge8, UCHAR *nt_password_hash_hash) {
    if (response != NULL) {
        memset(response, 0, 24);
    }
}

void MsChapV2Client_GenerateResponse(UCHAR *response, UCHAR *challenge8, UCHAR *nt_password_hash_hash) {
    if (response != NULL) {
        memset(response, 0, 24);
    }
}

// ============================================================================
// Removed Server Files Stubs (AzureClient, Admin, DDNS, Layer3, etc.)
// ============================================================================

// AzureClient.c
void FreeAzureClient(void *c) {}
bool AcGetEnable(void *c) { return false; }
void AcSetEnable(void *c, bool b) {}
void AcApplyCurrentConfig(void *c, void *internet_setting) {}

// DDNS.c  
void FreeDDNSClient(void *c) {}

// Layer3.c
void FreeCedarLayer3(void *c) {}

// Admin.c / RPC functions
void AdminAccept(void *c, void *sock) {}
bool AdminReconnect(void *a) { return false; }
void FreeRpcEnumSession(void *t) {}
void FreeRpcSessionStatus(void *t) {}
void FreeRpcEnumMacTable(void *t) {}
void FreeRpcEnumIpTable(void *t) {}
void FreeRpcEnumLogFile(void *t) {}
void FreeRpcReadLogFile(void *t) {}
void InRpcEnumSession(void *t, void *p) {}
void InRpcEnumMacTable(void *t, void *p) {}
void InRpcEnumIpTable(void *t, void *p) {}
void InRpcEnumLogFile(void *t, void *p) {}
void InRpcInternetSetting(void *t, void *p) {}
void OutRpcInternetSetting(void *t, void *p) {}

// EAP / MS-CHAPv2 (Sam.c)
bool EapClientSendMsChapv2AuthRequest(void *e) { return false; }

// Link.c (Cascade connections)
void *NewLink(void *cedar, void *hc, void *o, void *auth) { return NULL; }
void ReleaseLink(void *k) {}
void StartAllLink(void *h) {}
void StopAllLink(void *h) {}
void ReleaseAllLink(void *h) {}
void SetLinkOnline(void *k) {}
void SetLinkOffline(void *k) {}

// Layer3.c (L3 switch)
void InitCedarLayer3(void *c) {}
void *L3AddSw(void *c, void *t) { return NULL; }
void ReleaseL3Sw(void *s) {}
bool L3AddIf(void *s, char *name, UINT ip, UINT mask) { return false; }
bool L3AddTable(void *s, void *t) { return false; }
void *L3GetNextPacket(void *s, UINT *dst_if_id) { return NULL; }
void L3PutPacket(void *s, void *p, UINT src_if_id) {}
void L3SwStart(void *s) {}
void L3FreeAllSw(void *c) {}

// DDNS.c (Dynamic DNS)
void *NewDDNSClient(void *cedar, void *c) { return NULL; }

// AzureClient.c (VPN Gate)
void *NewAzureClient(void *cedar, void *c) { return NULL; }

// Radius.c (RADIUS auth)
bool RadiusLogin(void *c, char *server, UINT port, UCHAR *secret, UINT secret_size, 
                 wchar_t *username, char *password) { return false; }

// Admin.c / RPC serialization
void InRpcNodeInfo(void *t, void *p) {}
void OutRpcNodeInfo(void *p, void *t) {}
void InRpcWinVer(void *t, void *p) {}
void OutRpcWinVer(void *p, void *t) {}
void InRpcSessionStatus(void *t, void *p) {}
void OutRpcSessionStatus(void *p, void *t) {}
void OutRpcEnumSession(void *p, void *t) {}
void OutRpcEnumMacTable(void *p, void *t) {}
void OutRpcEnumIpTable(void *p, void *t) {}
void InRpcReadLogFile(void *t, void *p) {}
void OutRpcReadLogFile(void *p, void *t) {}
void OutRpcEnumLogFile(void *p, void *t) {}

// Admin.c / Server info functions
void SiEnumLocalSession(void *s, void *hubname, void *t) {}
void SiEnumSessionMain(void *s, void *t) {}
void SiEnumMacTable(void *s, char *hubname, void *t) {}
void SiEnumIpTable(void *s, char *hubname, void *t) {}
void SiEnumLocalLogFileList(void *s, char *hubname, void *t) {}
void SiReadLocalLogFile(void *s, char *filepath, UINT offset, void *t) {}

// Session status
void StGetSessionStatus(void *s, void *st) {}

// EAP client (Sam.c)
void *NewEapClient(void *sock, char *client_ip_str, char *username, char *hubname) { return NULL; }
void ReleaseEapClient(void *e) {}
bool PeapClientSendMsChapv2AuthRequest(void *e) { return false; }

// ============================================================================
// Virtual.c Stubs - Virtual host adapter (software mode)
// We always use TUN devices, so Virtual Host mode is not needed
// ============================================================================

// Generate MAC address for virtual adapter
void GenMacAddress(UCHAR *mac) {
    // Return dummy MAC: 00:AC:01:23:45:67
    if (mac) {
        mac[0] = 0x00; mac[1] = 0xAC; mac[2] = 0x01;
        mac[3] = 0x23; mac[4] = 0x45; mac[5] = 0x67;
    }
}

// Virtual host NAT option setter (not used - we use real TUN)
void NatSetHubOption(void *nat, void *o) {
    // No-op: We don't use virtual NAT
}

// Virtual host option setter (not used - we use real TUN)
void SetVirtualHostOption(void *v, void *option) {
    // No-op: We don't use virtual host mode
}

// Virtual adapter packet retrieval (not used - we use real TUN)
UINT VirtualGetNextPacket(void *v, void **data) {
    // Return 0 = no packet available
    return 0;
}

// Virtual adapter packet injection (not used - we use real TUN)
void VirtualPutPacket(void *v, void *data, UINT size) {
    // No-op: We don't use virtual host mode
}

// ============================================================================
// UdpAccel.c Stubs - UDP Acceleration (performance optimization)
// Not critical for basic VPN functionality - we use TCP connection
// ============================================================================

// UDP acceleration structure type
typedef struct UDP_ACCEL UDP_ACCEL;

// Create new UDP acceleration context
UDP_ACCEL *NewUdpAccel(void *cedar, void *ip, bool client_mode, bool random_port, bool no_nat_t) {
    return NULL; // Return NULL = UDP acceleration disabled
}

// Free UDP acceleration
void FreeUdpAccel(UDP_ACCEL *a) {
    // No-op: Nothing to free
}

// Poll UDP acceleration (main processing loop)
void UdpAccelPoll(UDP_ACCEL *a) {
    // No-op: No UDP acceleration
}

// Send block via UDP
void UdpAccelSendBlock(UDP_ACCEL *a, void *b) {
    // No-op: No UDP acceleration
}

// Calculate MSS for UDP
UINT UdpAccelCalcMss(UDP_ACCEL *a) {
    return 0; // Return 0 = no UDP acceleration
}

// Send data via UDP
void UdpAccelSend(UDP_ACCEL *a, UCHAR *data, UINT data_size, UCHAR flag, UINT max_size, bool high_priority) {
    // No-op: No UDP acceleration
}

// Check if UDP send is ready
bool UdpAccelIsSendReady(UDP_ACCEL *a, bool check_keepalive) {
    return false; // Always false = no UDP acceleration
}

// Calculate encryption key
void UdpAccelCalcKey(UCHAR *key, UCHAR *common_key, UCHAR *iv) {
    // No-op: No UDP acceleration
}

// Set tick for UDP acceleration
void UdpAccelSetTick(UDP_ACCEL *a, UINT64 tick64) {
    // No-op: No UDP acceleration
}

// Initialize UDP acceleration (server side)
bool UdpAccelInitServer(UDP_ACCEL *a, UCHAR *client_key, void *client_ip, UINT client_port, void *client_ip_2) {
    return false; // Failed = no UDP acceleration
}

// UDP acceleration (client side)
bool UdpAccelInitClient(UDP_ACCEL *a, UCHAR *server_key, void *server_ip, UINT server_port, UINT server_cookie, UINT client_cookie, void *server_ip_2) {
    return false; // Failed = no UDP acceleration
}

#endif // VPN_CLIENT_ONLY


