/*
 * Task Explorer -
 *   qt wrapper and helper functions
 *
 * Copyright (C) 2009-2016 wj32
 * Copyright (C) 2017-2019 dmex
 * Copyright (C) 2019-2023 David Xanatos
 *
 * This file is part of Task Explorer and contains System Informer code.
 *
 */

#include "stdafx.h"
#include "../../../MiscHelpers/Common/Settings.h"
#include "../../../MiscHelpers/Common/Common.h"
#include "../../../MiscHelpers/Common/ProgressDialog.h"
#include "../../../MiscHelpers/Archive/Archive.h"
#include "../GUI/TaskExplorer.h"
#include "ProcessHacker.h"
#include <kphmsgdyn.h>
extern "C" {
#include <kphdyndata.h>
}
#include <settings.h>
#include <psapi.h>

QString CastPhString(PPH_STRING phString, bool bDeRef)
{
	QString qString;
	if (phString)
	{
		qString = QString::fromWCharArray(phString->Buffer, phString->Length / sizeof(wchar_t));
		if (bDeRef)
			PhDereferenceObject(phString);
	}
	return qString;
}

PPH_STRING CastQString(const QString& qString)
{
	std::wstring wstr = qString.toStdWString();
	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, (wchar_t*)wstr.c_str());
	return PhCreateStringFromUnicodeString(&ustr);
}

/*
BOOLEAN PhInitializeNamespacePolicy(
	VOID
)
{
	HANDLE mutantHandle;
	WCHAR objectName[PH_INT64_STR_LEN_1];
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING objectNameUs;
	PH_FORMAT format[2];

	PhInitFormatS(&format[0], L"PhMutant_");
	PhInitFormatU(&format[1], HandleToUlong(NtCurrentProcessId()));

	if (!PhFormatToBuffer(
		format,
		RTL_NUMBER_OF(format),
		objectName,
		sizeof(objectName),
		NULL
	))
	{
		return FALSE;
	}

	RtlInitUnicodeString(&objectNameUs, objectName);
	InitializeObjectAttributes(
		&objectAttributes,
		&objectNameUs,
		OBJ_CASE_INSENSITIVE,
		PhGetNamespaceHandle(),
		NULL
	);

	if (NT_SUCCESS(NtCreateMutant(
		&mutantHandle,
		MUTANT_QUERY_STATE,
		&objectAttributes,
		TRUE
	)))
	{
		return TRUE;
	}

	return FALSE;
}
*/

VOID PhpEnablePrivileges(
	VOID
)
{
	HANDLE tokenHandle;

	if (NT_SUCCESS(PhOpenProcessToken(
		NtCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES,
		&tokenHandle
	)))
	{
		CHAR privilegesBuffer[FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) + sizeof(LUID_AND_ATTRIBUTES) * 9];
		PTOKEN_PRIVILEGES privileges;
		ULONG i;

		privileges = (PTOKEN_PRIVILEGES)privilegesBuffer;
		privileges->PrivilegeCount = 9;

		for (i = 0; i < privileges->PrivilegeCount; i++)
		{
			privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
			privileges->Privileges[i].Luid.HighPart = 0;
		}

		privileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
		privileges->Privileges[1].Luid.LowPart = SE_INC_BASE_PRIORITY_PRIVILEGE;
		privileges->Privileges[2].Luid.LowPart = SE_INC_WORKING_SET_PRIVILEGE;
		privileges->Privileges[3].Luid.LowPart = SE_LOAD_DRIVER_PRIVILEGE;
		privileges->Privileges[4].Luid.LowPart = SE_PROF_SINGLE_PROCESS_PRIVILEGE;
		privileges->Privileges[5].Luid.LowPart = SE_BACKUP_PRIVILEGE;
		privileges->Privileges[6].Luid.LowPart = SE_RESTORE_PRIVILEGE;
		privileges->Privileges[7].Luid.LowPart = SE_SHUTDOWN_PRIVILEGE;
		privileges->Privileges[8].Luid.LowPart = SE_TAKE_OWNERSHIP_PRIVILEGE;

		NtAdjustPrivilegesToken(
			tokenHandle,
			FALSE,
			privileges,
			0,
			NULL,
			NULL
		);

		NtClose(tokenHandle);
	}
}

HMODULE GetThisModuleHandle()
{
    //Returns module handle where this function is running in: EXE or DLL
    HMODULE hModule = NULL;
    ::GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, 
        (LPCTSTR)GetThisModuleHandle, &hModule);

    return hModule;
}

// Hook: NtMapViewOfSection

#include "WinHelpers/FuncHook/HookUtils.h"

typedef NTSTATUS (*P_NtMapViewOfSection)(
	IN  HANDLE SectionHandle,
	IN  HANDLE ProcessHandle,
	IN  OUT PVOID *BaseAddress,
	IN  ULONG_PTR ZeroBits,
	IN  SIZE_T CommitSize,
	IN  OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN  OUT PSIZE_T ViewSize,
	IN  ULONG InheritDisposition,
	IN  ULONG AllocationType,
	IN  ULONG Protect);

P_NtMapViewOfSection NtMapViewOfSectionTramp = NULL;

bool IsMemoryReadable(PVOID Address)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(Address, &mbi, sizeof(mbi)) == 0)
		return false;

	if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))
		return true;

	return false;
}

NTSTATUS NTAPI MyMapViewOfSection(
	IN  HANDLE SectionHandle,
	IN  HANDLE ProcessHandle,
	IN  OUT PVOID* BaseAddress,
	IN  ULONG_PTR ZeroBits,
	IN  SIZE_T CommitSize,
	IN  OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN  OUT PSIZE_T ViewSize,
	IN  ULONG InheritDisposition,
	IN  ULONG AllocationType,
	IN  ULONG Protect)
{
	NTSTATUS status = NtMapViewOfSectionTramp(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
	if (NT_SUCCESS(status) && !g_MyCrashHandlerExceptionFilter_Engaged)
	{
		if (BaseAddress && *BaseAddress && !IsMemoryReadable(*BaseAddress))
		{
			DbgPrint("MyMapViewOfSection: Invalid BaseAddress: %p", *BaseAddress);
			status = STATUS_ACCESS_DENIED;
		}
	}
	return status;
}

int InitPH()
{
	HINSTANCE Instance = GetThisModuleHandle(); // (HINSTANCE)::GetModuleHandle(NULL);
	LONG result;

	//
	// If a dll is not signed like a shell extension for the default windows file open dialog,
	// or alike, we have a problem as our driver when ImageLoadProtection == TRUE will block the loading of the dll
	// and unmap the just loaded section from the driver, so we add a sanity check for NtMapViewOfSection
	// if it returns no error but the memory is not readable return STATUS_ACCESS_DENIED instead.
	//

	HookFunction(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtMapViewOfSection"), MyMapViewOfSection, (VOID**)&NtMapViewOfSectionTramp);

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

	//if (!NT_SUCCESS(PhInitializePhLibEx(L"Task Explorer", ULONG_MAX, Instance, 0, 0)))
	if (!NT_SUCCESS(PhInitializePhLib(L"Task Explorer")))
		return 1;
	//if (!PhInitializeExceptionPolicy())
	//	return 1;
	//if (!PhInitializeNamespacePolicy())
	//	return 1;
	//if (!PhInitializeMitigationPolicy())
	//	return 1;
	//if (!PhInitializeRestartPolicy())
	//    return 1;

	KphInitialize();

	//PhpProcessStartupParameters();
	PhpEnablePrivileges();

	PhSettingsInitialization();
    //PhpInitializeSettings();
	// note: this is needed to open the permissions panel
	PhpAddIntegerSetting(L"EnableSecurityAdvancedDialog", L"1");
	PhpAddStringSetting(L"FileBrowseExecutable", L"%SystemRoot%\\explorer.exe /select,\"%s\"");
	// for permissions diaog on win 7
	PhpAddIntegerSetting(L"EnableThemeSupport", L"0");
	PhpAddIntegerSetting(L"GraphColorMode", L"1");
	PhpAddIntegerSetting(L"TreeListBorderEnable", L"0");

	return 0;
}

bool (*g_KernelProcessMonitor)(quint64 ProcessId, quint64 ParentId, const QString& FileName, const QString& CommandLine) = NULL;

void (*g_KernelDebugLogger)(const QString& Output) = NULL;

extern "C" {

static VOID NTAPI KsiCommsCallback(
    _In_ ULONG_PTR ReplyToken,
    _In_ PCKPH_MESSAGE Message
    )
{
	//static QMap<void*,int> killMap;
	//static QMutex killMutex;
	switch (Message->Header.MessageId)
	{
		case KphMsgProcessCreate:
		{
			PPH_FREE_LIST freelist = KphGetMessageFreeList();

			PKPH_MESSAGE msg = (PKPH_MESSAGE)PhAllocateFromFreeList(freelist);
			KphMsgInit(msg, KphMsgProcessCreate);
			if (g_KernelProcessMonitor) 
			{
				quint64 ProcessId = (quint64)Message->Kernel.ProcessCreate.TargetProcessId;
				quint64 ParentId = (quint64)Message->Kernel.ProcessCreate.ParentProcessId;

				QString FileName;
				UNICODE_STRING fileName = { 0 };
				if (NT_SUCCESS(KphMsgDynGetUnicodeString(Message, KphMsgFieldFileName, &fileName))) {
					PPH_STRING oldFileName = PhCreateString(fileName.Buffer);
					PPH_STRING newFileName = PhGetFileName(oldFileName);
					PhDereferenceObject(oldFileName);
					FileName = CastPhString(newFileName);
				}

				QString CommandLine;
				UNICODE_STRING commandLine = { 0 };
				if (NT_SUCCESS(KphMsgDynGetUnicodeString(Message, KphMsgFieldCommandLine, &commandLine)))
					CommandLine = QString::fromWCharArray(commandLine.Buffer, commandLine.Length / sizeof(wchar_t));

				msg->Reply.ProcessCreate.CreationStatus = g_KernelProcessMonitor(ProcessId, ParentId, FileName, CommandLine) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
			}
			else
				msg->Reply.ProcessCreate.CreationStatus = STATUS_SUCCESS;
			KphCommsReplyMessage(ReplyToken, msg);

			PhFreeToFreeList(freelist, msg);

			break;
		}
		case KphMsgDebugPrint:
		{
			ANSI_STRING aStr;
			if (NT_SUCCESS(KphMsgDynGetAnsiString(Message, KphMsgFieldOutput, &aStr)))
			{
				if(g_KernelDebugLogger)
					g_KernelDebugLogger(QString::fromLatin1(aStr.Buffer, aStr.Length));
			}
			break;
		}
		/*case KphMsgFilePreCreate:
		{
			PPH_FREE_LIST freelist = KphGetMessageFreeList();

			PKPH_MESSAGE msg = (PKPH_MESSAGE)PhAllocateFromFreeList(freelist);
			KphMsgInit(msg, KphMsgFilePreCreate);
			msg->Reply.File.Pre.Create.Status = STATUS_SUCCESS;

			UNICODE_STRING fileName = { 0 };
			if (NT_SUCCESS(KphMsgDynGetUnicodeString(Message, KphMsgFieldFileName, &fileName))) {
				QString Name = QString::fromWCharArray(fileName.Buffer, fileName.Length / sizeof(WCHAR));
				if (Name.startsWith("\\Device\\ImDisk")) {
					qDebug() << "BAM:" << Name;
					QMutexLocker Lock(&killMutex);
					killMap[Message->Kernel.File.FileObject]++;
				}
			}

			KphCommsReplyMessage(ReplyToken, msg);

			PhFreeToFreeList(freelist, msg);

			break;
		}
		case KphMsgFilePostCreate:
		{
			PPH_FREE_LIST freelist = KphGetMessageFreeList();

			PKPH_MESSAGE msg = (PKPH_MESSAGE)PhAllocateFromFreeList(freelist);
			KphMsgInit(msg, KphMsgFilePostCreate);
			msg->Reply.File.Post.Create.Status = STATUS_SUCCESS;

			{
				QMutexLocker Lock(&killMutex);
				if (killMap[Message->Kernel.File.FileObject])
				{
					msg->Reply.File.Post.Create.Status = STATUS_ACCESS_DENIED;
					killMap[Message->Kernel.File.FileObject]--;
					qDebug() << "BAM: !!!";
				}
			}


			KphCommsReplyMessage(ReplyToken, msg);

			PhFreeToFreeList(freelist, msg);

			break;
		}*/
	}
}

NTSTATUS KsiReadConfiguration(
	const QString &Path,
	_In_ PCWSTR FileName,
	_Out_ PBYTE* Data,
	_Out_ PULONG Length
)
{
	NTSTATUS status;
	//PPH_STRING fileName;
	HANDLE fileHandle;

	*Data = NULL;
	*Length = 0;

	status = STATUS_NO_SUCH_FILE;

	//fileName = PhGetApplicationDirectoryFileNameZ(FileName, TRUE);
	//if (fileName)
	{
		//if (NT_SUCCESS(status = PhCreateFile(
		if (NT_SUCCESS(status = PhCreateFileWin32(
			&fileHandle,
		//	&fileName->sr,
			(wchar_t*)(Path + "\\" + QString::fromWCharArray(FileName)).utf16(),
			FILE_GENERIC_READ,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
		)))
		{
			status = PhGetFileData(fileHandle, (PVOID*)Data, Length);

			NtClose(fileHandle);
		}

		//PhDereferenceObject(fileName);
	}

	return status;
}

/*NTSTATUS KsiValidateDynamicConfiguration(
	_In_ PBYTE DynData,
	_In_ ULONG DynDataLength
)
{
	NTSTATUS status;
	PPH_STRING fileName;
	PVOID versionInfo;
	VS_FIXEDFILEINFO* fileInfo;

	status = STATUS_NO_SUCH_FILE;

	if (fileName = PhGetKernelFileName2())
	{
		if (versionInfo = PhGetFileVersionInfoEx(&fileName->sr))
		{
			if (fileInfo = PhGetFileVersionFixedInfo(versionInfo))
			{
				status = KphDynDataGetConfiguration(
					(PKPH_DYNDATA)DynData,
					DynDataLength,
					HIWORD(fileInfo->dwFileVersionMS),
					LOWORD(fileInfo->dwFileVersionMS),
					HIWORD(fileInfo->dwFileVersionLS),
					LOWORD(fileInfo->dwFileVersionLS),
					NULL
				);
			}

			PhFree(versionInfo);
		}

		PhDereferenceObject(fileName);
	}

	return status;
}*/

NTSTATUS KsiGetDynData(
	const QString &Path,
	_Out_ PBYTE* DynData,
	_Out_ PULONG DynDataLength,
	_Out_ PBYTE* Signature,
	_Out_ PULONG SignatureLength
)
{
	NTSTATUS status;
	PBYTE data = NULL;
	ULONG dataLength;
	PBYTE sig = NULL;
	ULONG sigLength;

	*DynData = NULL;
	*DynDataLength = 0;
	*Signature = NULL;
	*SignatureLength = 0;

	bool bUseNew = QFile::exists(Path + "\\new_ksidyn.bin");

	status = KsiReadConfiguration(Path, bUseNew ? L"new_ksidyn.bin" : L"ksidyn.bin", &data, &dataLength);
	if (!NT_SUCCESS(status))
		goto CleanupExit;

	//status = KsiValidateDynamicConfiguration(data, dataLength);
	//if (!NT_SUCCESS(status))
	//	goto CleanupExit;

	status = KsiReadConfiguration(Path, bUseNew ? L"new_ksidyn.sig" : L"ksidyn.sig", &sig, &sigLength);
	if (!NT_SUCCESS(status))
		goto CleanupExit;
	
	if (!sigLength)
	{
		status = STATUS_SI_DYNDATA_INVALID_SIGNATURE;
		goto CleanupExit;
	}

	*DynDataLength = dataLength;
	*DynData = data;
	data = NULL;

	*SignatureLength = sigLength;
	*Signature = sig;
	sig = NULL;

	status = STATUS_SUCCESS;

CleanupExit:
	if (data)
		PhFree(data);
	if (sig)
		PhFree(sig);

	return status;
}

}

PPH_STRING KsiServiceName = NULL;
BOOLEAN KsiEnableLoadNative = FALSE;
BOOLEAN KsiEnableLoadFilter = FALSE;

BOOLEAN KsiEnableUnloadProtection = FALSE;

BOOLEAN g_KphStartupMax = FALSE;
BOOLEAN g_KphStartupHigh = FALSE;

NTSTATUS PhRestartSelf(
	_In_ PPH_STRINGREF AdditionalCommandLine
)
{
#ifndef DEBUG
	static ULONG64 mitigationFlags[] =
	{
		(PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON |
		PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON |
		PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON |
		PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON |
		// PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON |
		PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON ),
		(PROCESS_CREATION_MITIGATION_POLICY2_LOADER_INTEGRITY_CONTINUITY_ALWAYS_ON |
		// PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON |
		// PROCESS_CREATION_MITIGATION_POLICY2_BLOCK_NON_CET_BINARIES_ALWAYS_ON |
		// PROCESS_CREATION_MITIGATION_POLICY2_XTENDED_CONTROL_FLOW_GUARD_ALWAYS_ON |
		PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON)
	};
#endif
	NTSTATUS status;
	PPROC_THREAD_ATTRIBUTE_LIST attributeList = NULL;
	PH_STRINGREF commandlineSr;
	PPH_STRING commandline;
	STARTUPINFOEX startupInfo;

	status = PhGetProcessCommandLineStringRef(&commandlineSr);

	if (!NT_SUCCESS(status))
		return status;

	commandline = PhConcatStringRef2(
		&commandlineSr,
		AdditionalCommandLine
	);

#ifndef DEBUG
	status = PhInitializeProcThreadAttributeList(&attributeList, 1);

	if (!NT_SUCCESS(status))
		return status;

	if (WindowsVersion >= WINDOWS_10_22H2)
	{
		status = PhUpdateProcThreadAttribute(
			attributeList,
			PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
			mitigationFlags,
			sizeof(ULONG64) * 2
		);
	}
	else
	{
		status = PhUpdateProcThreadAttribute(
			attributeList,
			PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
			mitigationFlags,
			sizeof(ULONG64) * 1
		);
	}
#endif

	if (!NT_SUCCESS(status))
		return status;

	memset(&startupInfo, 0, sizeof(STARTUPINFOEX));
	startupInfo.StartupInfo.cb = sizeof(STARTUPINFOEX);
	startupInfo.lpAttributeList = attributeList;

	status = PhCreateProcessWin32Ex(
		NULL,
		PhGetString(commandline),
		NULL,
		NULL,
		&startupInfo,
		PH_CREATE_PROCESS_DEFAULT_ERROR_MODE | PH_CREATE_PROCESS_EXTENDED_STARTUPINFO,
		NULL,
		NULL,
		NULL,
		NULL
	);

	if (NT_SUCCESS(status))
	{
		PhExitApplication(STATUS_SUCCESS);
	}

	if (attributeList)
		PhDeleteProcThreadAttributeList(attributeList);

	PhDereferenceObject(commandline);

	return status;
}

BOOLEAN PhDoesOldKsiExist(
	VOID
)
{
	static PH_STRINGREF ksiOld = PH_STRINGREF_INIT(L"ksi.dll-old");
	BOOLEAN result = FALSE;
	PPH_STRING applicationDirectory;
	PPH_STRING fileName;

	if (!(applicationDirectory = PhGetApplicationDirectory()))
		return FALSE;

	if (fileName = PhConcatStringRef2(&applicationDirectory->sr, &ksiOld))
	{
		if (result = PhDoesFileExist(&fileName->sr))
		{
			// If the file exists try to delete it. If we can't a reboot is
			// still required since it's likely still mapped into the kernel.
			if (NT_SUCCESS(PhDeleteFile(&fileName->sr)))
				result = FALSE;
		}

		PhDereferenceObject(fileName);
	}

	PhDereferenceObject(applicationDirectory);
	return result;
}

bool IsOnARM64()
{
	HMODULE Kernel32 = GetModuleHandleW(L"Kernel32.dll");
	typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS2)(HANDLE, PUSHORT, PUSHORT);
	LPFN_ISWOW64PROCESS2 pIsWow64Process2 = (LPFN_ISWOW64PROCESS2)GetProcAddress(Kernel32, "IsWow64Process2");
	if (pIsWow64Process2)
	{
		USHORT ProcessMachine = 0xFFFF;
		USHORT NativeMachine = 0xFFFF;
		BOOL ok = pIsWow64Process2(GetCurrentProcess(), &ProcessMachine, &NativeMachine);

		if (NativeMachine == IMAGE_FILE_MACHINE_ARM64)
			return true;
	}
	return false;
}

bool g_KsiDynDataLoaded = false;

STATUS InitKSI(const QString& AppDir)
{
	QString FileName = theConf->GetString("OptionsKSI/FileName", "SystemInformer.sys");
	QString ServiceName = theConf->GetString("OptionsKSI/DeviceName", "KTaskExplorer");
	QString ObjectName = "\\Driver\\" + ServiceName;
	QString PortName = "\\" + ServiceName;
	QString Altitude = theConf->GetString("OptionsKSI/Altitude", "385210.8");

	KsiEnableLoadNative = theConf->GetBool("OptionsKSI/EnableLoadNative", false);
	KsiEnableLoadFilter = theConf->GetBool("OptionsKSI/EnableLoadFilter", false);

	// if the file name is not a full path Add the application directory
	if (!FileName.contains("\\")) 
	{
		if (IsOnARM64())
			FileName = AppDir + "\\ARM64\\" + FileName;
		else
			FileName = AppDir + "\\AMD64\\" + FileName;
	}

	FileName = FileName.replace("/", "\\");
	if (!QFile::exists(FileName))
		return ERR(QObject::tr("The kernel driver file '%1' was not found.").arg(FileName), STATUS_NOT_FOUND);

	if (!PhGetOwnTokenAttributes().Elevated)
		return ERR("Driver required administrative privileges.", STATUS_ELEVATION_REQUIRED);

	if(PhIsExecutingInWow64())
		return ERR("Driver only supports 64 bit.", STATUS_IMAGE_MACHINE_TYPE_MISMATCH);

	NTSTATUS status;

	// todo: fix-me
	//if (PhDoesOldKsiExist())
	//{
	//    if (PhGetIntegerSetting(L"EnableKphWarnings") && !PhStartupParameters.PhSvc)
	//    {
	//        PhShowKsiError(
	//            L"Unable to load kernel driver, the last System Informer update requires a reboot.",
	//            STATUS_PENDING 
	//            );
	//    }
	//    return;
	//}

	STATUS Status = OK;
	KsiServiceName = CastQString(ServiceName);
	PPH_STRING ksiFileName = CastQString(FileName);
	PPH_STRING objectName = CastQString(ObjectName);
	PPH_STRING portName = CastQString(PortName);
	PPH_STRING altitude = CastQString(Altitude);

	UNICODE_STRING fileName;
	WCHAR buffer[MAX_PATH];
	DWORD size = GetProcessImageFileNameW(GetCurrentProcess(), buffer, MAX_PATH);
	wcsrchr(buffer, L'\\')[0] = 0;
	UNICODE_STRING ustr;
	RtlInitUnicodeString(&ustr, buffer);
	PPH_STRING clientPath = PhCreateStringFromUnicodeString(&ustr);

	KPH_CONFIG_PARAMETERS config = { 0 };
	config.FileName = &ksiFileName->sr;
	config.ServiceName = &KsiServiceName->sr;
	config.ObjectName = &objectName->sr;
	config.PortName = &portName->sr;
	config.Altitude = &altitude->sr;

	config.FsSupportedFeatures = 0; // not yet in driver?
	if (theConf->GetBool("OptionsKSI/EnableFsFeatureOffloadRead", false))
		SetFlag(config.FsSupportedFeatures, SUPPORTED_FS_FEATURES_OFFLOAD_READ);
	if (theConf->GetBool("OptionsKSI/EnableFsFeatureOffloadWrite", false))
		SetFlag(config.FsSupportedFeatures, SUPPORTED_FS_FEATURES_OFFLOAD_WRITE);
	if (theConf->GetBool("OptionsKSI/EnableFsFeatureQueryOpen", false))
		SetFlag(config.FsSupportedFeatures, SUPPORTED_FS_FEATURES_QUERY_OPEN);
	if (theConf->GetBool("OptionsKSI/EnableFsFeatureBypassIO", false))
		SetFlag(config.FsSupportedFeatures, SUPPORTED_FS_FEATURES_BYPASS_IO);

	config.Flags.Flags = 0;
#ifdef _DEBUG 
	config.Flags.DisableImageLoadProtection = theConf->GetBool("OptionsKSI/DisableImageLoadProtection", false);
	config.Flags.AllowDebugging = theConf->GetBool("OptionsKSI/AllowDebugging", true);
#else
	config.Flags.DisableImageLoadProtection = theConf->GetBool("OptionsKSI/DisableImageLoadProtection", false);
	config.Flags.AllowDebugging = theConf->GetBool("OptionsKSI/AllowDebugging", false);
#endif
	config.Flags.RandomizedPoolTag = theConf->GetBool("OptionsKSI/RandomizedPoolTag", false);
#ifdef _DEBUG 
	config.Flags.DynDataNoEmbedded = theConf->GetBool("OptionsKSI/DynDataNoEmbedded", true);
#else
	config.Flags.DynDataNoEmbedded = theConf->GetBool("OptionsKSI/DynDataNoEmbedded", false);
#endif

	config.ClientPath = &clientPath->sr;

	config.EnableNativeLoad = KsiEnableLoadNative;
	config.EnableFilterLoad = KsiEnableLoadFilter;

	config.Callback = (PKPH_COMMS_CALLBACK)KsiCommsCallback;

	status = KphConnect(&config);
	if (!NT_SUCCESS(status))
		Status = ERR("KphConnect Failed.", status);
	else
	{
		KPH_LEVEL level = KphLevelEx(FALSE);

		PBYTE dynData = NULL;
		ULONG dynDataLength;
		PBYTE signature = NULL;
		ULONG signatureLength;

		status = KsiGetDynData(Split2(FileName, "\\", true).first, &dynData, &dynDataLength, &signature, &signatureLength);
		if (!NT_SUCCESS(status))
			Status = ERR("Unsupported windows version.", STATUS_UNKNOWN_REVISION);
		else
		{
			status = KphActivateDynData(dynData, dynDataLength, signature, signatureLength);
			if (!NT_SUCCESS(status))
				Status = ERR("KphActivateDynData Failed.", status);
			else
				g_KsiDynDataLoaded = true;
		}

		if (signature)
			PhFree(signature);
		if (dynData)
			PhFree(dynData);

		// Medium level indicates protection failed to be applied presumably due to missing dyndata
		// if level is other we try restarting procedure to gain higher trust level
		// is we got stuck on medium level and dyndata load failes we bug out
		if (NT_SUCCESS(status) || level != KphLevelMed)
		{
			QStringList Info;

			KPH_PROCESS_STATE processState = KphGetCurrentProcessState();
			if ((processState != 0) && (processState & KPH_PROCESS_STATE_MAXIMUM) != KPH_PROCESS_STATE_MAXIMUM)
			{
				if (!BooleanFlagOn(processState, KPH_PROCESS_SECURELY_CREATED))
					Info.append("not securely created");
				if (!BooleanFlagOn(processState, KPH_PROCESS_VERIFIED_PROCESS))
					Info.append("unverified primary image");
				if (!BooleanFlagOn(processState, KPH_PROCESS_PROTECTED_PROCESS))
					Info.append("inactive protections");
				if (!BooleanFlagOn(processState, KPH_PROCESS_NO_UNTRUSTED_IMAGES))
					Info.append("unsigned images (likely an unsigned plugin)");
				if (!BooleanFlagOn(processState, KPH_PROCESS_NOT_BEING_DEBUGGED))
					Info.append("process is being debugged");
				if ((processState & KPH_PROCESS_STATE_MINIMUM) != KPH_PROCESS_STATE_MINIMUM)
					Info.append("tampered primary image");
			}

			Status = OK;

			if ((level != KphLevelMax))
			{
				Status = ERR(QString("Unable to access the kernel driver: %1.").arg(Info.join(", ")), STATUS_ACCESS_DENIED);

				if (config.Flags.AllowDebugging || !NtCurrentPeb()->BeingDebugged)
				{
					if ((level == KphLevelHigh) && !g_KphStartupMax)
					{
						PH_STRINGREF commandline = PH_STRINGREF_INIT(L" -kx");
						status = PhRestartSelf(&commandline);
					}

					if ((level < KphLevelHigh) && !g_KphStartupMax && !g_KphStartupHigh)
					{
						PH_STRINGREF commandline = PH_STRINGREF_INIT(L" -kh");
						status = PhRestartSelf(&commandline);
					}

					if (!NT_SUCCESS(status))
						Status = ERR("PhRestartSelf failed.", STATUS_ACCESS_DENIED);
				}
			}

			if (level == KphLevelMax)
			{
				ACCESS_MASK process = 0;
				ACCESS_MASK thread = 0;

				if (theConf->GetBool("OptionsKSI/EnableUnloadProtection", false)) {
					if(NT_SUCCESS(KphAcquireDriverUnloadProtection(NULL, NULL)))
						KsiEnableUnloadProtection = TRUE;
				}

				switch (theConf->GetInt("OptionsKSI/ClientProcessProtectionLevel", 0))
				{
				case 2:
					process |= (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
					thread |= (THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION);
					__fallthrough;
				case 1:
					process |= (PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME);
					thread |= (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_RESUME);
					__fallthrough;
				case 0:
				default:
					break;
				}

				if (process != 0 || thread != 0)
					KphStripProtectedProcessMasks(NtCurrentProcess(), process, thread);
			}
		}
	}

	if (ksiFileName)
		PhDereferenceObject(ksiFileName);
	if (objectName)
		PhDereferenceObject(objectName);
	if (altitude)
		PhDereferenceObject(altitude);
	if (portName)
		PhDereferenceObject(portName);
	if (clientPath)
		PhDereferenceObject(clientPath);

//#ifdef DEBUG
//	KsiDebugLogInitialize();
//#endif

	return Status;
}

STATUS CleanupKSI()
{
	NTSTATUS status;
	KPH_CONFIG_PARAMETERS config = { 0 };
	BOOLEAN shouldUnload;

	if (!KphCommsIsConnected())
		return OK;

	if (KsiEnableUnloadProtection) {
		KphReleaseDriverUnloadProtection(NULL, NULL);
		KsiEnableUnloadProtection = FALSE;
	}

	if (theConf->GetBool("OptionsKSI/UnloadOnExit", true))
	{
		ULONG clientCount;

		if (!NT_SUCCESS(status = KphGetConnectedClientCount(&clientCount)))
			return status;

		shouldUnload = (clientCount == 1);
	}
	else
	{
		shouldUnload = FALSE;
	}

	KphCommsStop();
//#ifdef DEBUG
//	KsiDebugLogFinalize();
//#endif

	if (!shouldUnload)
		return OK;

	if (KsiServiceName)
	{
		config.ServiceName = &KsiServiceName->sr;
		config.EnableNativeLoad = KsiEnableLoadNative;
		config.EnableFilterLoad = KsiEnableLoadFilter;
		status = KphServiceStop(&config);

		PhDereferenceObject(KsiServiceName);
	}

	if(!NT_SUCCESS(status))
		return ERR("KphServiceStop Failed.", status);
	return OK;
}

STATUS TryUpdateDynData(const QString& AppDir)
{
	STATUS Status;

	CProgressDialog Progress(CTaskExplorer::tr("Updating DynData"));
	QNetworkAccessManager Manager;

	QString Folder = theConf->GetConfigDir() + "\\Temp";
	QDir().mkpath(Folder);

	auto FailWithMessage = [&](const QString& Message) {
		Status = ERR(Message, STATUS_UNSUCCESSFUL);
		Progress.OnProgressMessage(Message);
		QTimer::singleShot(3000, [&] {Progress.close();});
	};

	auto ApplyUpdate = [&](const QString& FileName){

		CArchive Archive(FileName);

		if (Archive.Open() != ERR_7Z_OK) {
			FailWithMessage(CTaskExplorer::tr("Failed to open archive."));
			return;
		}

		bool IsBoxArchive = false;

		QMap<int, QIODevice*> Files;

		int bin = Archive.FindByPath(IsOnARM64() ? "arm64/ksidyn.bin" : "amd64/ksidyn.bin");
		int sig = Archive.FindByPath(IsOnARM64() ? "arm64/ksidyn.sig" : "amd64/ksidyn.sig");

		if (bin == -1 || sig == -1) {
			FailWithMessage(CTaskExplorer::tr("DynData not found in archive."));
#ifndef _DEBUG
			QFile::remove(FileName);
#endif
			return;
		}

		QString DrvPath;
		QString DrvFileName = theConf->GetString("OptionsKSI/FileName", "SystemInformer.sys");
		if (DrvFileName.contains("\\")) 
			DrvPath = Split2(DrvFileName, "\\", true).first;
		else if (IsOnARM64())
			DrvPath = AppDir + "\\ARM64";
		else
			DrvPath = AppDir + "\\AMD64";

		QFile::remove(DrvPath + "\\new_ksidyn.bin");
		QFile::remove(DrvPath + "\\new_ksidyn.sig");

		Files.insert(bin, new QFile(DrvPath + "\\new_ksidyn.bin"));
		Files.insert(sig, new QFile(DrvPath + "\\new_ksidyn.sig"));

		if (!Archive.Extract(&Files)) {
			FailWithMessage(CTaskExplorer::tr("Failed to extreact files."));
#ifndef _DEBUG
			QFile::remove(FileName);
#endif
			return;
		}

#ifndef _DEBUG
		QFile::remove(FileName);
#endif
		Archive.Close(); Progress.OnProgressMessage(CTaskExplorer::tr("Updated DynData successfully"));
		QTimer::singleShot(3000, [&] {Progress.close(); });
	};

	QScopedPointer<QNetworkReply> DlReply;
	auto DownloadSI = [&](const QString& sUrl) {

		QUrl DlUrl(sUrl);

		QString FileName = Folder + "\\" + DlUrl.fileName();

		if (QFile::exists(FileName)) {
#ifdef _DEBUG
			Progress.OnProgressMessage(CTaskExplorer::tr("Latest SI build already downloaded"));
			ApplyUpdate(FileName);
			return;
#else
			QFile::remove(FileName);
#endif
		}

		QNetworkRequest DlRequest(DlUrl);
		DlRequest.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

		DlReply.reset(Manager.get(DlRequest));

		QObject::connect(DlReply.data(), &QNetworkReply::downloadProgress, &Manager, [&](qint64 bytes, qint64 bytesTotal) {
			if (bytesTotal != 0)
				Progress.OnProgressMessage(CTaskExplorer::tr("Downloading latest SI build"), 100 * bytes / bytesTotal);
		});

		QObject::connect(DlReply.data(), &QNetworkReply::finished, &Manager, [&, FileName]() {

			if (DlReply->error() != QNetworkReply::NoError) {
				QString Error = DlReply->errorString();
				FailWithMessage(CTaskExplorer::tr("Download Failed, Error: %1").arg(Error));
				return;
			}

			QFile File(FileName);
			if (!File.open(QIODevice::WriteOnly)) {
				FailWithMessage(CTaskExplorer::tr("Failed to open file for writing."));
				return;
			}
			File.write(DlReply->readAll());
			File.close();

			Progress.OnProgressMessage(CTaskExplorer::tr("Successfully Downloaded latest SI build"));
			ApplyUpdate(FileName);
		});
	};

	QScopedPointer<QNetworkReply> Reply;
	auto GetUpdate = [&](){

		QString sUrl = theConf->GetString("OptionsKSI/SIUpdateUrl", "https://systeminformer.dev/update?channel=canary");
		
		QUrl Url(sUrl);
		
		QNetworkRequest Request(Url);
		Request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);

		Reply.reset(Manager.get(Request));

		QObject::connect(Reply.data(), &QNetworkReply::finished, &Manager, [&]() {

			if (Reply->error() != QNetworkReply::NoError) {
				QString Error = Reply->errorString();
				FailWithMessage(CTaskExplorer::tr("Update Check Failed, Error: %1").arg(Error));
				return;
			}
			//QString Location = Reply->header(QNetworkRequest::LocationHeader).toString();

			QByteArray Json = Reply->readAll();
			QVariantMap Data = QJsonDocument::fromJson(Json).toVariant().toMap();
			QString BinUrl = Data["bin_url"].toString();
			if (BinUrl.isEmpty()) {
				FailWithMessage(CTaskExplorer::tr("Update Check Failed, Error: Unrecognized Reply"));
				return;
			}

			DownloadSI(BinUrl);
		});
	};

	GetUpdate();

	Progress.exec();

	return Status;
}

bool KphSetDebugLog(bool Enable)
{
	NTSTATUS status;
	KPH_INFORMER_SETTINGS Settings;
	if (NT_SUCCESS(status = KphGetInformerSettings(&Settings))) {
		Settings.DebugPrint = Enable;
		status = KphSetInformerSettings(&Settings);
	}
	return NT_SUCCESS(status);
}

bool KphSetSystemMon(bool Enable)
{
	if (!KphCommsIsConnected())
		return false;

	NTSTATUS status;
	KPH_INFORMER_SETTINGS Settings;
	if (NT_SUCCESS(status = KphGetInformerSettings(&Settings))) {
		Settings.ProcessCreate = Enable;
		status = KphSetInformerSettings(&Settings);
	}
	return NT_SUCCESS(status);
}

bool KphGetSystemMon()
{
	if (!KphCommsIsConnected())
		return false;

	KPH_INFORMER_SETTINGS Settings;
	if (NT_SUCCESS(KphGetInformerSettings(&Settings)))
		return Settings.ProcessCreate;
	return false;
}

static PPH_STRING KsiKernelFileName = NULL;
static PPH_STRING KsiKernelVersion = NULL;

PPH_STRING KsiGetKernelFileNameInternal(VOID)
{
	NTSTATUS status;
	UCHAR buffer[FIELD_OFFSET(RTL_PROCESS_MODULES, Modules) + sizeof(RTL_PROCESS_MODULE_INFORMATION)] = { 0 };
	PRTL_PROCESS_MODULES modules;
	ULONG modulesLength;

	modules = (PRTL_PROCESS_MODULES)buffer;
	modulesLength = sizeof(buffer);

	status = NtQuerySystemInformation(
		SystemModuleInformation,
		modules,
		modulesLength,
		&modulesLength
	);

	if (status != STATUS_SUCCESS && status != STATUS_INFO_LENGTH_MISMATCH)
		return NULL;
	if (status == STATUS_SUCCESS || modules->NumberOfModules < 1)
		return NULL;

	return PhConvertUtf8ToUtf16((PCSTR)modules->Modules[0].FullPathName);
}

PPH_STRING KsiGetKernelFileName(VOID)
{
	static PH_INITONCE initOnce = PH_INITONCE_INIT;

	if (PhBeginInitOnce(&initOnce))
	{
		KsiKernelFileName = KsiGetKernelFileNameInternal();

		PhEndInitOnce(&initOnce);
	}

	if (KsiKernelFileName)
		return (PPH_STRING)PhReferenceObject(KsiKernelFileName);

	return NULL;
}

PPH_STRING KsiGetKernelVersionString(VOID)
{
	static PH_INITONCE initOnce = PH_INITONCE_INIT;

	if (PhBeginInitOnce(&initOnce))
	{
		PPH_STRING fileName;
		PH_IMAGE_VERSION_INFO versionInfo;

		if (fileName = KsiGetKernelFileName())
		{
			if (PhInitializeImageVersionInfoEx(&versionInfo, &fileName->sr, FALSE))
			{
				KsiKernelVersion = versionInfo.FileVersion;

				versionInfo.FileVersion = NULL;
				PhDeleteImageVersionInfo(&versionInfo);
			}

			PhDereferenceObject(fileName);
		}

		PhEndInitOnce(&initOnce);
	}

	if (KsiKernelVersion)
		return (PPH_STRING)PhReferenceObject(KsiKernelVersion);

	return NULL;
}

void PhShowAbout(QWidget* parent)
{
		QString AboutCaption = QString(
			"<h3>System Informer</h3>"
			"<p>Licensed Under the MIT License</p>"
			"<p>Copyright (c) 2022</p>"
		);
		QString AboutText = QString(
                "<p>Thanks to:<br>"
                "    <a href=\"https://github.com/wj32\">wj32</a> - Wen Jia Liu<br>"
                "    <a href=\"https://github.com/dmex\">dmex</a> - Steven G<br>"
                "    <a href=\"https://github.com/jxy-s\">jxy-s</a> - Johnny Shaw<br>"
                "    <a href=\"https://github.com/ionescu007\">ionescu007</a> - Alex Ionescu<br>"
                "    <a href=\"https://github.com/yardenshafir\">yardenshafir</a> - Yarden Shafir<br>"
                "    <a href=\"https://github.com/winsiderss/systeminformer/graphs/contributors\">Contributors</a> - thank you for your additions!<br>"
                "    Donors - thank you for your support!</p>"
                "<p>System Informer uses the following components:<br>"
                "    <a href=\"https://github.com/michaelrsweet/mxml\">Mini-XML</a> by Michael Sweet<br>"
                "    <a href=\"https://www.pcre.org\">PCRE</a><br>"
                "    <a href=\"https://github.com/json-c/json-c\">json-c</a><br>"
                "    MD5 code by Jouni Malinen<br>"
                "    SHA1 code by Filip Navara, based on code by Steve Reid<br>"
                "    <a href=\"http://www.famfamfam.com/lab/icons/silk\">Silk icons</a><br>"
                "    <a href=\"https://www.fatcow.com/free-icons\">Farm-fresh web icons</a><br></p>"
			"<p></p>"
			"<p>Visit <a href=\"https://github.com/winsiderss/systeminformer\">System Informer on github</a> for more information.</p>"
		);
		QMessageBox *msgBox = new QMessageBox(parent);
		msgBox->setAttribute(Qt::WA_DeleteOnClose);
		msgBox->setWindowTitle(QString("About ProcessHacker Library"));
		msgBox->setText(AboutCaption);
		msgBox->setInformativeText(AboutText);

		QIcon ico(QLatin1String(":/ProcessHacker.png"));
		msgBox->setIconPixmap(ico.pixmap(64, 64));
#if defined(Q_WS_WINCE)
		msgBox->setDefaultButton(msgBox->addButton(QMessageBox::Ok));
#endif
		
		msgBox->exec();
}

extern "C" {
	VOID NTAPI PhAddDefaultSettings()
	{
	}

	VOID NTAPI PhUpdateCachedSettings()
	{
	}
}

