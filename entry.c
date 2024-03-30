#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "beacon.h"

void GetLoggedOn(const char * hostname){

    DWORD i = 0, j = 0, retCode = 0;
    DWORD dwresult = 0;
    HKEY rootkey = 0;
    HKEY RemoteKey = 0;
    int sessionCount = 0;
    wchar_t whostname[256] = {0};
    DWORD whostname_len = 256;


    if(hostname == NULL)
    {
        internal_printf("[*] Querying local registry...\n");
        dwresult = ADVAPI32$RegOpenKeyExA(HKEY_USERS, NULL, 0, KEY_READ, &rootkey);

        if(dwresult){ goto END;}

        // get Fqdn name for localhost
        KERNEL32$GetComputerNameExW(ComputerNameDnsFullyQualified, (LPWSTR)&whostname, &whostname_len);
    }
    else
    {
        internal_printf("[*] Querying registry on %s...\n", hostname);
        dwresult = ADVAPI32$RegConnectRegistryA(hostname, HKEY_USERS, &RemoteKey);

        if(dwresult){
            internal_printf("failed to connect");
            goto END;
        }
        dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, NULL, 0, KEY_READ, &rootkey);

        if(dwresult){
            internal_printf("failed to open remote key");
            goto END;
        }
    }

    DWORD index = 0;
    CHAR subkeyName[256];
    DWORD subkeyNameSize = sizeof(subkeyName);

    while ((dwresult = ADVAPI32$RegEnumKeyExA(rootkey, index, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS) {
        BOOL isSID = TRUE;
        // if the subkey starts with S-1-5-21 and does not have an underscore, print
        if (subkeyName[0] == 'S' && subkeyName[1] == '-' && subkeyName[2] == '1' && subkeyName[3] == '-' && subkeyName[4] == '5' && subkeyName[5] == '-' && subkeyName[6] == '2' && subkeyName[7] == '1') {
            // if the subkey has an underscore anywhere in the string, skip
            for (j = 0; j < subkeyNameSize; j++) {
                if (subkeyName[j] == '_') {
                    isSID = FALSE;
                    break;
                }
            }
            if (isSID) {
                PSID pSid = NULL;
                WCHAR szName[128]; // Allocate memory for the account name
                WCHAR szDomain[128]; // Allocate memory for the domain
                DWORD dwNameSize = _countof(szName);
                DWORD dwDomainSize = _countof(szDomain);
                SID_NAME_USE SidType;

                internal_printf("[*] Sessions on the machine:\n");
                // Convert string SID to a valid PSID
                if (ADVAPI32$ConvertStringSidToSidA(subkeyName, &pSid)) {
                    // Attempt to resolve the SID to an account name and domain
                    if (ADVAPI32$LookupAccountSidW(NULL, pSid, szName, &dwNameSize, szDomain, &dwDomainSize, &SidType)) {
                        internal_printf("\t[+] Account Name: %S\\%S\n", szDomain, szName);
                    } else {
                        internal_printf("[-] Failed to lookup Account SID\n");
                    }

                    KERNEL32$LocalFree(pSid);
                } else {
                    internal_printf("[-] Failed to convert string SID to PSID\n");
                }

                sessionCount++;

            }
        }

        // Move to the next subkey
        index++;
        subkeyNameSize = sizeof(subkeyName);
    }

    internal_printf("[*] Found %d sessions in the registry\n", sessionCount);

    if (dwresult != ERROR_NO_MORE_ITEMS) {
        goto END;
    }



    END:
    if(rootkey){
        ADVAPI32$RegCloseKey(rootkey);
    }

    if(RemoteKey)
        ADVAPI32$RegCloseKey(RemoteKey);

    return;
}

#ifdef BOF

VOID go(
        IN PCHAR Buffer,
        IN ULONG Length
)
{
    datap parser = {0};
    const char * hostname = NULL;

    DWORD dwresult = 0;

    BeaconDataParse(&parser, Buffer, Length);
    hostname = BeaconDataExtract(&parser, NULL);


    //correct hostname param
    if(*hostname == 0)
    {
        hostname = NULL;
    }

    if(!bofstart())
    {
        return;
    }

    GetLoggedOn(hostname);
    printoutput(TRUE);
};

#else

int main()
{
    Reg_EnumKey(NULL);
    Reg_EnumKey("Oxenfurt");
    Reg_EnumKey("192.168.0.215");
    return 0;
}

#endif