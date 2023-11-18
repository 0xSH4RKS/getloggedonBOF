#include <windows.h>
#include <ntsecapi.h>
#include <ntstatus.h>
#include "beacon.h"
#include "bofdefs.h"
#include "base.c"

void LookupAccountSids(LSA_HANDLE PolicyHandle, PSID *Sids, ULONG Count) {

    LSA_REFERENCED_DOMAIN_LIST *ReferencedDomains = NULL;
    LSA_TRANSLATED_NAME *Names = NULL;
    NTSTATUS Status;
    PSID MySid;
    SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;


    Status = LsaLookupSids(PolicyHandle, Count, Sids, &ReferencedDomains, &Names);
    if (ERROR_SUCCESS != Status) {
        if (Status == STATUS_SOME_NOT_MAPPED) {
            internal_printf("Some SIDs could not be mapped to names.\n");
        } else {
            internal_printf("LsaLookupSids failed. Error: 0x%lx\n", LsaNtStatusToWinError(Status));
            return;
        }
    }

    for (ULONG i = 0; i < Count; i++) {
        if (Names[i].Use != SidTypeUnknown && Names[i].Use != SidTypeInvalid) {
            // Allocate buffer for domain and name
            WCHAR DomainBuffer[256] = {0};
            WCHAR NameBuffer[256] = {0};

            // Copy the domain name
            wcsncpy_s(DomainBuffer, _countof(DomainBuffer), ReferencedDomains->Domains[Names[i].DomainIndex].Name.Buffer, ReferencedDomains->Domains[Names[i].DomainIndex].Name.Length / sizeof(WCHAR));

            // Copy the account name
            wcsncpy_s(NameBuffer, _countof(NameBuffer), Names[i].Name.Buffer, Names[i].Name.Length / sizeof(WCHAR));

            // Print the domain and name
            internal_printf("SID %lu: %S\\%S\n", i, DomainBuffer, NameBuffer);
        } else {
            internal_printf("SID %lu: Unknown or Invalid\n", i);
        }
    }

    if (ReferencedDomains) {
        LsaFreeMemory(ReferencedDomains);
    }
    if (Names) {
        LsaFreeMemory(Names);
    }
}

DWORD getloggedon(const char * hostname) {
    DWORD dwresult = ERROR_SUCCESS;
    HKEY hive = HKEY_LOCAL_MACHINE;
    HKEY RemoteKey = NULL;
    HKEY rootkey = NULL;
    TCHAR szKeyName[256];
    DWORD dwKeyNameSize;
    DWORD dwIndex = 0;
    FILETIME ftLastWriteTime;
    LSA_HANDLE PolicyHandle = NULL;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    PSID *SidArray = NULL;
    ULONG SidCount = 0;
    ULONG MaxSidCount = 256; // Adjust as needed

    // Connect to the remote device registry
    dwresult = ADVAPI32$RegConnectRegistryA(hostname, hive, &RemoteKey);
    if (dwresult != ERROR_SUCCESS) {
        internal_printf("RegConnectRegistryA failed (%lX)\n", dwresult);
        return dwresult;
    }

    // Parse reg keys with user information
    dwresult = ADVAPI32$RegOpenKeyExA(RemoteKey, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0, KEY_READ, &rootkey);
    if (dwresult != ERROR_SUCCESS) {
        internal_printf("RegOpenKeyExA failed (%lX)\n", dwresult);
        ADVAPI32$RegCloseKey(RemoteKey);
        return dwresult;
    }

    // Allocate memory for the SID array
    SidArray = (PSID *)intAlloc(sizeof(PSID) * MaxSidCount);
    if (!SidArray) {
        internal_printf("Memory allocation failed for SID array.\n");
        ADVAPI32$RegCloseKey(rootkey);
        ADVAPI32$RegCloseKey(RemoteKey);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    // Initialize an LSA_OBJECT_ATTRIBUTES structure
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    // Open the policy handle
    NTSTATUS status = LsaOpenPolicy(NULL, &ObjectAttributes, POLICY_LOOKUP_NAMES, &PolicyHandle);
    if (status != STATUS_SUCCESS) {
        internal_printf("LsaOpenPolicy failed. Error: 0x%lx\n", LsaNtStatusToWinError(status));
        intFree(SidArray);
        ADVAPI32$RegCloseKey(rootkey);
        ADVAPI32$RegCloseKey(RemoteKey);
        return LsaNtStatusToWinError(status);
    }

    // Enumerate the subkeys to get the SIDs
    while (TRUE) {
        dwKeyNameSize = sizeof(szKeyName) / sizeof(szKeyName[0]);
        dwresult = ADVAPI32$RegEnumKeyExA(rootkey, dwIndex, szKeyName, &dwKeyNameSize, NULL, NULL, NULL, &ftLastWriteTime);
        if (dwresult == ERROR_NO_MORE_ITEMS) {
            break; // No more entries to retrieve
        } else if (dwresult != ERROR_SUCCESS) {
            break; // Handle error
        }

        // Convert the string SID to a binary SID
        PSID pSid = NULL;
        if (ADVAPI32$ConvertStringSidToSidA(szKeyName, &pSid)) {
            // Add the SID to the array
            SidArray[SidCount] = pSid;
            SidCount++;
            // Check if we have reached the maximum count
            if (SidCount >= MaxSidCount) {
                break; // We've filled the SID array
            }
        } else {
            DWORD dwError = KERNEL32$GetLastError();
            internal_printf("ConvertStringSidToSidA failed (%lX)\n", dwError);
        }

        dwIndex++;
    }

    // Now that we have an array of SIDs, resolve them to account names
    if (SidCount > 0) {
        LookupAccountSids(PolicyHandle, SidArray, SidCount);
    }

    // Clean up
    for (ULONG i = 0; i < SidCount; i++) {
        if (SidArray[i] != NULL) {
            KERNEL32$LocalFree(SidArray[i]); // Free each SID
        }
    }
    if (SidArray != NULL) {
        intFree(SidArray); // Free the array of SIDs
    }
    if (PolicyHandle != NULL) {
        LsaClose(PolicyHandle); // Close the LSA policy handle
    }
    if (rootkey != NULL) {
        ADVAPI32$RegCloseKey(rootkey); // Close the root key
    }
    if (RemoteKey != NULL) {
        ADVAPI32$RegCloseKey(RemoteKey); // Close the remote registry key
    }

    return dwresult;
}

#ifdef BOF
VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	DWORD dwErrorCode = ERROR_SUCCESS;
	//		$args = bof_pack($1, $packstr, $hostname, $hive, $path, $key, $type, $value);
	datap parser = {0};
	const char * hostname = NULL;
	HKEY hive = (HKEY)0x80000000;
	const char * path = NULL;
	const char * key = NULL;
	DWORD type = 0;
	const void * data = NULL;
	DWORD datalen = 0;
	int t = 0;

	BeaconDataParse(&parser, Buffer, Length);
	hostname = BeaconDataExtract(&parser, NULL);
	t = BeaconDataInt(&parser);
	#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
	#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
	hive = (HKEY)((DWORD) hive + (DWORD)t);
	#pragma GCC diagnostic pop
	path = BeaconDataExtract(&parser, NULL);
	key = BeaconDataExtract(&parser, NULL);
	type = BeaconDataInt(&parser);
	data = BeaconDataExtract(&parser, (int *)&datalen);

	if(type == REG_QWORD)
	{
		DWORD val = *(int*)data;
		data = intAlloc(sizeof(QWORD));
		memcpy((char *)data, &val, 4);
		datalen = sizeof(QWORD);
	}

	//correct hostname param
	if(*hostname == 0)
	{
		hostname = NULL;
	}

	if(!bofstart())
	{
		return;
	}

    internal_printf("Getting all logged on users from: %s\n", hostname);

    dwErrorCode = getloggedon(hostname);
    if (dwErrorCode != ERROR_SUCCESS) { // Corrected the condition here
        BeaconPrintf(CALLBACK_ERROR, "getloggedon failed: %lX\n", dwErrorCode);
        goto go_end;
    }

    // print out the logged on users

    internal_printf("SUCCESS.\n");

go_end:
	printoutput(TRUE);

	bofstop();
};
#else
#define TEST_HOSTNAME "commando"
int main(int argc, char ** argv)
{

    DWORD dwErrorCode = ERROR_SUCCESS;
    LPCSTR lpszHostName = TEST_HOSTNAME;

    //correct hostname param
    if(*lpszHostName == 0)
    {
        lpszHostName = NULL;
    }

    internal_printf("Getting all logged on users from: %s\n", lpszHostName);

    dwErrorCode = getloggedon(lpszHostName);
    if (dwErrorCode != ERROR_SUCCESS) { // Corrected the condition here
        BeaconPrintf(CALLBACK_ERROR, "getloggedon failed: %lX\n", dwErrorCode);
        goto main_end;
    }

    // print out the logged on users

    internal_printf("SUCCESS.\n");

    main_end:
    return dwErrorCode;
}
#endif