/*
 * nns.h - .NET NegotiateStream Protocol
 *
 * Functions for handling .NET's NegotiateStream secure transport protocol
 * including SSPI/Kerberos authentication and encrypted communication.
 */

#ifndef NNS_H
#define NNS_H

#define SECURITY_WIN32

#ifdef BOF
#include "bofdefs.h"

DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleW(LPWSTR, LPWSTR, ULONG, PLUID, PVOID, PVOID,
                                                                         PVOID, PCredHandle, PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextW(PCtxtHandle, PCtxtHandle, LPWSTR, ULONG,
                                                                          ULONG, ULONG, PSecBufferDesc, ULONG,
                                                                          PCtxtHandle, PSecBufferDesc, PULONG,
                                                                          PTimeStamp);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$QueryContextAttributesW(PCtxtHandle, ULONG, PVOID);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$EncryptMessage(PCtxtHandle, ULONG, PSecBufferDesc, ULONG);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$DecryptMessage(PCtxtHandle, PSecBufferDesc, ULONG, PULONG);
DECLSPEC_IMPORT SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(PVOID);
#else
#include <security.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#define NNS_HANDSHAKE_IN_PROGRESS 0x16
#define NNS_HANDSHAKE_DONE 0x14
#define NNS_MAJOR_VERSION 1
#define NNS_MINOR_VERSION 0

#define NMF_PREAMBLE_ACK 0x0B
#define NMF_PREAMBLE_END 0x0C
#define NMF_SIZED_ENVELOPE 0x06

typedef struct CONNECTION_CONTEXT
{
    SOCKET socket;
    BOOL isConnected;
    WSADATA wsaData;
    CredHandle hCred;
    CtxtHandle hContext;
    BOOL hasContext;
    BOOL isAuthenticated;
    SecPkgContext_Sizes sizes;
} CONNECTION_CONTEXT;

BOOL PerformNNSHandshake(CONNECTION_CONTEXT *ctx, const char *target);
BOOL NNSSendMessage(SOCKET socket, BYTE type, PBYTE data, DWORD dataLen);
BOOL NNSReceiveMessage(SOCKET socket, BYTE *type, PBYTE *data, DWORD *dataLen);
BOOL NNSSendEncrypted(CONNECTION_CONTEXT *ctx, PBYTE data, DWORD dataLen);
BOOL NNSReceiveEncrypted(CONNECTION_CONTEXT *ctx, PBYTE *data, DWORD *dataLen);

// Perform NNS authentication handshake
BOOL PerformNNSHandshake(CONNECTION_CONTEXT *ctx, const char *target)
{
    SECURITY_STATUS status;
    SecBufferDesc outBufferDesc;
    SecBuffer outBuffer;
    SecBufferDesc inBufferDesc;
    SecBuffer inBuffer;
    ULONG contextAttr;
    TimeStamp expiry;
    WCHAR targetSPN[512];
    BYTE *tokenBuffer = NULL;
    BYTE *recvBuffer = NULL;
    DWORD tokenSize = 0;
    BYTE messageType;
    BOOL firstCall = TRUE;

    // Needs ADWS/ prefix for Kerberos
    char spnNarrow[512];
    MSVCRT$memset(targetSPN, 0, sizeof(targetSPN));
    MSVCRT$sprintf(spnNarrow, "ADWS/%s", target);
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, spnNarrow, -1, targetSPN, 256);

    status = SECUR32$AcquireCredentialsHandleW(NULL, L"Negotiate", SECPKG_CRED_OUTBOUND, NULL, NULL, NULL, NULL,
                                               &ctx->hCred, &expiry);

    if (status != SEC_E_OK)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] AcquireCredentialsHandle failed: 0x%08X\n", status);
        return FALSE;
    }

    do
    {
        tokenBuffer = (BYTE *)intAlloc(16384);
        if (!tokenBuffer)
        {
            return FALSE;
        }

        outBuffer.BufferType = SECBUFFER_TOKEN;
        outBuffer.cbBuffer = 16384;
        outBuffer.pvBuffer = tokenBuffer;

        outBufferDesc.ulVersion = SECBUFFER_VERSION;
        outBufferDesc.cBuffers = 1;
        outBufferDesc.pBuffers = &outBuffer;

        if (!firstCall && recvBuffer)
        {
            inBuffer.BufferType = SECBUFFER_TOKEN;
            inBuffer.cbBuffer = tokenSize;
            inBuffer.pvBuffer = recvBuffer;

            inBufferDesc.ulVersion = SECBUFFER_VERSION;
            inBufferDesc.cBuffers = 1;
            inBufferDesc.pBuffers = &inBuffer;
        }

        status = SECUR32$InitializeSecurityContextW(&ctx->hCred, firstCall ? NULL : &ctx->hContext, targetSPN,
                                                    ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY |
                                                        ISC_REQ_INTEGRITY | ISC_REQ_MUTUAL_AUTH |
                                                        ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_EXTENDED_ERROR,
                                                    0, SECURITY_NETWORK_DREP, firstCall ? NULL : &inBufferDesc, 0,
                                                    &ctx->hContext, &outBufferDesc, &contextAttr, &expiry);

        ctx->hasContext = TRUE;
        firstCall = FALSE;

        if (outBuffer.cbBuffer > 0)
        {

            if (!NNSSendMessage(ctx->socket, NNS_HANDSHAKE_IN_PROGRESS, (PBYTE)outBuffer.pvBuffer, outBuffer.cbBuffer))
            {
                intFree(tokenBuffer);
                SECUR32$FreeContextBuffer(outBuffer.pvBuffer);
                return FALSE;
            }
        }

        if (outBuffer.pvBuffer)
        {
            SECUR32$FreeContextBuffer(outBuffer.pvBuffer);
        }
        intFree(tokenBuffer);

        if (status == SEC_I_CONTINUE_NEEDED)
        {
            if (recvBuffer)
            {
                intFree(recvBuffer);
                recvBuffer = NULL;
            }

            if (!NNSReceiveMessage(ctx->socket, &messageType, &recvBuffer, &tokenSize))
            {
                return FALSE;
            }

            if (messageType != NNS_HANDSHAKE_IN_PROGRESS)
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[-] Unexpected message type: 0x%02X\n", messageType);
                intFree(recvBuffer);
                return FALSE;
            }
        }

    } while (status == SEC_I_CONTINUE_NEEDED);

    if (status != SEC_E_OK)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Authentication failed: 0x%08X\n", status);
        return FALSE;
    }

    if (recvBuffer)
    {
        intFree(recvBuffer);
        recvBuffer = NULL;
    }

    BYTE *doneBuffer = NULL;
    DWORD doneSize = 0;
    if (!NNSReceiveMessage(ctx->socket, &messageType, &doneBuffer, &doneSize))
    {
        return FALSE;
    }

    if (messageType != NNS_HANDSHAKE_DONE)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Expected HANDSHAKE_DONE, got: 0x%02X\n", messageType);
        intFree(doneBuffer);
        return FALSE;
    }

    intFree(doneBuffer);

    // Query context for sizes before encryption
    status = SECUR32$QueryContextAttributesW(&ctx->hContext, SECPKG_ATTR_SIZES, &ctx->sizes);
    if (status != SEC_E_OK)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] QueryContextAttributes failed: 0x%08X\n", status);
        return FALSE;
    }

    BYTE preambleEnd = NMF_PREAMBLE_END;
    if (!NNSSendEncrypted(ctx, &preambleEnd, 1))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to send encrypted preamble end\n");
        return FALSE;
    }

    PBYTE response = NULL;
    DWORD responseLen = 0;
    if (!NNSReceiveEncrypted(ctx, &response, &responseLen))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Failed to receive encrypted preamble ack\n");
        return FALSE;
    }

    if (responseLen != 1 || response[0] != NMF_PREAMBLE_ACK)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Invalid preamble ack: 0x%02X\n", response[0]);
        intFree(response);
        return FALSE;
    }

    intFree(response);

    ctx->isAuthenticated = TRUE;
    return TRUE;
}

// Send NNS message with header
BOOL NNSSendMessage(SOCKET socket, BYTE type, PBYTE data, DWORD dataLen)
{
    BYTE *buffer = (BYTE *)intAlloc(5 + dataLen);
    if (!buffer)
        return FALSE;

    buffer[0] = type;
    buffer[1] = 0x01;
    buffer[2] = 0x00;
    buffer[3] = (BYTE)((dataLen >> 8) & 0xFF);
    buffer[4] = (BYTE)(dataLen & 0xFF);

    if (data && dataLen > 0)
    {
        MSVCRT$memcpy(buffer + 5, data, dataLen);
    }

    int ret = WS2_32$send(socket, (char *)buffer, 5 + dataLen, 0);
    intFree(buffer);

    return (ret != SOCKET_ERROR);
}

// Receive NNS message, handling partial receives also
BOOL NNSReceiveMessage(SOCKET socket, BYTE *type, PBYTE *data, DWORD *dataLen)
{
    BYTE header[5];
    int ret;
    int total = 0;

    // Receive header
    while (total < 5)
    {
        ret = WS2_32$recv(socket, (char *)(header + total), 5 - total, 0);
        if (ret <= 0)
        {
            return FALSE;
        }
        total += ret;
    }

    *type = header[0];
    *dataLen = (header[3] << 8) | header[4];

    if (*dataLen > 0)
    {
        *data = (PBYTE)intAlloc(*dataLen);
        if (!*data)
            return FALSE;

        // Receive payload
        total = 0;
        while (total < (int)*dataLen)
        {
            ret = WS2_32$recv(socket, (char *)(*data + total), *dataLen - total, 0);
            if (ret <= 0)
            {
                intFree(*data);
                return FALSE;
            }
            total += ret;
        }
    }
    else
    {
        *data = NULL;
    }

    return TRUE;
}

// Send encrypted NNS message
BOOL NNSSendEncrypted(CONNECTION_CONTEXT *ctx, PBYTE data, DWORD dataLen)
{
    SecBufferDesc messageDesc;
    SecBuffer messageBuffers[3];
    SECURITY_STATUS status;
    BYTE *sendBuffer = NULL;
    DWORD sendLen;
    int ret;

    // Allocate buffer for encrypted data
    sendLen = ctx->sizes.cbSecurityTrailer + dataLen + ctx->sizes.cbBlockSize;
    sendBuffer = (BYTE *)intAlloc(sendLen + 4);
    if (!sendBuffer)
        return FALSE;

    // Setup buffers
    messageBuffers[0].BufferType = SECBUFFER_TOKEN;
    messageBuffers[0].cbBuffer = ctx->sizes.cbSecurityTrailer;
    messageBuffers[0].pvBuffer = sendBuffer + 4;

    messageBuffers[1].BufferType = SECBUFFER_DATA;
    messageBuffers[1].cbBuffer = dataLen;
    messageBuffers[1].pvBuffer = sendBuffer + 4 + ctx->sizes.cbSecurityTrailer;
    MSVCRT$memcpy(messageBuffers[1].pvBuffer, data, dataLen);

    messageBuffers[2].BufferType = SECBUFFER_PADDING;
    messageBuffers[2].cbBuffer = ctx->sizes.cbBlockSize;
    messageBuffers[2].pvBuffer = sendBuffer + 4 + ctx->sizes.cbSecurityTrailer + dataLen;

    messageDesc.ulVersion = SECBUFFER_VERSION;
    messageDesc.cBuffers = 3;
    messageDesc.pBuffers = messageBuffers;

    status = SECUR32$EncryptMessage(&ctx->hContext, 0, &messageDesc, 0);
    if (status != SEC_E_OK)
    {
        intFree(sendBuffer);
        return FALSE;
    }

    // Calculate total encrypted size
    sendLen = messageBuffers[0].cbBuffer + messageBuffers[1].cbBuffer + messageBuffers[2].cbBuffer;

    // Write length header (little-endian)
    sendBuffer[0] = (BYTE)(sendLen & 0xFF);
    sendBuffer[1] = (BYTE)((sendLen >> 8) & 0xFF);
    sendBuffer[2] = (BYTE)((sendLen >> 16) & 0xFF);
    sendBuffer[3] = (BYTE)((sendLen >> 24) & 0xFF);

    ret = WS2_32$send(ctx->socket, (char *)sendBuffer, sendLen + 4, 0);
    intFree(sendBuffer);

    return (ret != SOCKET_ERROR);
}

// Receive encrypted NNS message - handles multiple chunks if needed
BOOL NNSReceiveEncrypted(CONNECTION_CONTEXT *ctx, PBYTE *data, DWORD *dataLen)
{
    BYTE lengthHeader[4];
    DWORD encryptedLen;
    BYTE *encryptedData = NULL;
    SecBufferDesc messageDesc;
    SecBuffer messageBuffers[2];
    SECURITY_STATUS status;
    int ret;
    int total = 0;

    // First receive the initial chunk
    // Receive length header
    while (total < 4)
    {
        ret = WS2_32$recv(ctx->socket, (char *)(lengthHeader + total), 4 - total, 0);
        if (ret <= 0)
        {
            int error = WS2_32$WSAGetLastError();
            BeaconPrintf(CALLBACK_OUTPUT, "[-] recv failed in length header: ret=%d, WSAError=%d\n", ret, error);
            return FALSE;
        }
        total += ret;
    }

    // Parse length (little-endian)
    encryptedLen = lengthHeader[0] | (lengthHeader[1] << 8) | (lengthHeader[2] << 16) | (lengthHeader[3] << 24);

    // Receive encrypted data
    encryptedData = (BYTE *)intAlloc(encryptedLen);
    if (!encryptedData)
        return FALSE;

    total = 0;
    while (total < (int)encryptedLen)
    {
        ret = WS2_32$recv(ctx->socket, (char *)(encryptedData + total), encryptedLen - total, 0);
        if (ret <= 0)
        {
            intFree(encryptedData);
            return FALSE;
        }
        total += ret;
    }

    // Setup buffers for decryption
    messageBuffers[0].BufferType = SECBUFFER_STREAM;
    messageBuffers[0].cbBuffer = encryptedLen;
    messageBuffers[0].pvBuffer = encryptedData;

    messageBuffers[1].BufferType = SECBUFFER_DATA;
    messageBuffers[1].cbBuffer = 0;
    messageBuffers[1].pvBuffer = NULL;

    messageDesc.ulVersion = SECBUFFER_VERSION;
    messageDesc.cBuffers = 2;
    messageDesc.pBuffers = messageBuffers;

    ULONG qop;
    status = SECUR32$DecryptMessage(&ctx->hContext, &messageDesc, 0, &qop);
    if (status != SEC_E_OK)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] DecryptMessage failed: 0x%08X\n", status);
        intFree(encryptedData);
        return FALSE;
    }

    // Find data buffer
    BYTE *decryptedData = NULL;
    DWORD decryptedLen = 0;
    for (ULONG i = 0; i < messageDesc.cBuffers; i++)
    {
        if (messageBuffers[i].BufferType == SECBUFFER_DATA)
        {
            decryptedLen = messageBuffers[i].cbBuffer;
            decryptedData = (BYTE *)messageBuffers[i].pvBuffer;
            break;
        }
    }

    if (!decryptedData || decryptedLen == 0)
    {
        intFree(encryptedData);
        return FALSE;
    }

    // Checks if this is a truncated NMF message that needs more data
    if (decryptedLen > 0 && decryptedData[0] == NMF_SIZED_ENVELOPE)
    {
        // Parse the NMF varint to see expected size
        DWORD offset = 1;
        DWORD expectedPayloadLen = 0;
        if (offset < decryptedLen)
        {
            BYTE firstByte = decryptedData[offset++];
            if ((firstByte & 0x80) == 0)
            {
                expectedPayloadLen = firstByte;
            }
            else
            {
                expectedPayloadLen = firstByte & 0x7F;
                int shift = 7;
                while (offset < decryptedLen && shift < 32)
                {
                    BYTE nextByte = decryptedData[offset++];
                    expectedPayloadLen |= (DWORD)(nextByte & 0x7F) << shift;
                    if ((nextByte & 0x80) == 0)
                        break;
                    shift += 7;
                }
            }

            DWORD totalExpected = offset + expectedPayloadLen;

            // If we need more data, receive additional chunks
            if (totalExpected > decryptedLen)
            {

                // Allocate buffer for complete message
                BYTE *fullMessage = (BYTE *)intAlloc(totalExpected + 1024);
                if (!fullMessage)
                {
                    intFree(encryptedData);
                    return FALSE;
                }

                MSVCRT$memcpy(fullMessage, decryptedData, decryptedLen);
                DWORD currentLen = decryptedLen;

                intFree(encryptedData);

                // Receive additional chunks
                while (currentLen < totalExpected)
                {
                    // Check if more data is available with MSG_PEEK
                    BYTE peekBuf[4];
                    ret = WS2_32$recv(ctx->socket, (char *)peekBuf, 4, MSG_PEEK);
                    if (ret <= 0)
                    {
                        break;
                    }

                    // Receive next chunk header
                    total = 0;
                    while (total < 4)
                    {
                        ret = WS2_32$recv(ctx->socket, (char *)(lengthHeader + total), 4 - total, 0);
                        if (ret <= 0)
                            break;
                        total += ret;
                    }
                    if (total < 4)
                        break;

                    // Parse chunk length
                    encryptedLen =
                        lengthHeader[0] | (lengthHeader[1] << 8) | (lengthHeader[2] << 16) | (lengthHeader[3] << 24);

                    // Receive chunk data
                    encryptedData = (BYTE *)intAlloc(encryptedLen);
                    if (!encryptedData)
                    {
                        intFree(fullMessage);
                        return FALSE;
                    }

                    total = 0;
                    while (total < (int)encryptedLen)
                    {
                        ret = WS2_32$recv(ctx->socket, (char *)(encryptedData + total), encryptedLen - total, 0);
                        if (ret <= 0)
                            break;
                        total += ret;
                    }
                    if (total < (int)encryptedLen)
                    {
                        intFree(encryptedData);
                        break;
                    }

                    // Decrypt chunk
                    messageBuffers[0].BufferType = SECBUFFER_STREAM;
                    messageBuffers[0].cbBuffer = encryptedLen;
                    messageBuffers[0].pvBuffer = encryptedData;
                    messageBuffers[1].BufferType = SECBUFFER_DATA;
                    messageBuffers[1].cbBuffer = 0;
                    messageBuffers[1].pvBuffer = NULL;

                    status = SECUR32$DecryptMessage(&ctx->hContext, &messageDesc, 0, &qop);
                    if (status != SEC_E_OK)
                    {
                        intFree(encryptedData);
                        break;
                    }

                    // Find decrypted data
                    for (ULONG i = 0; i < messageDesc.cBuffers; i++)
                    {
                        if (messageBuffers[i].BufferType == SECBUFFER_DATA)
                        {
                            DWORD chunkDataLen = messageBuffers[i].cbBuffer;
                            if (currentLen + chunkDataLen <= totalExpected + 1024)
                            {
                                MSVCRT$memcpy(fullMessage + currentLen, messageBuffers[i].pvBuffer, chunkDataLen);
                                currentLen += chunkDataLen;
                            }
                            break;
                        }
                    }

                    intFree(encryptedData);
                }

                // Return the assembled message
                *dataLen = currentLen;
                *data = fullMessage;
                return TRUE;
            }
        }
    }

    // Single chunk case, just copy and return
    *dataLen = decryptedLen;
    *data = (PBYTE)intAlloc(decryptedLen);
    if (*data)
    {
        MSVCRT$memcpy(*data, decryptedData, decryptedLen);
    }

    intFree(encryptedData);
    return (*data != NULL);
}

#endif
