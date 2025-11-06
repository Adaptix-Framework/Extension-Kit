/*
 * nmf.h - .NET Message Framing Protocol
 *
 * Functions for handling Microsoft's .NET Message Framing (NMF) protocol
 * which provides framing for SOAP messages over TCP.
 */

#ifndef NMF_H
#define NMF_H

#ifdef BOF
#include "bofdefs.h"
#else
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#define NMF_VERSION_RECORD 0x00
#define NMF_MODE_RECORD 0x01
#define NMF_VIA_RECORD 0x02
#define NMF_ENCODING_RECORD 0x03
#define NMF_SIZED_ENVELOPE 0x06
#define NMF_UPGRADE_REQUEST 0x09
#define NMF_UPGRADE_RESPONSE 0x0A
#define NMF_PREAMBLE_ACK 0x0B
#define NMF_PREAMBLE_END 0x0C

// CONNECTION_CONTEXT is defined in nns.h
typedef struct CONNECTION_CONTEXT CONNECTION_CONTEXT;
BOOL NNSSendEncrypted(CONNECTION_CONTEXT *ctx, PBYTE data, DWORD dataLen);

BOOL SendNMFHandshake(SOCKET socket, const char *target);
BOOL UnwrapNMFEnvelope(BYTE *nmfData, DWORD nmfLen, BYTE **nbfseData, DWORD *nbfseLen);
BOOL SendADWSMessage(CONNECTION_CONTEXT *ctx, BYTE *nbfseMessage, DWORD nbfseLen);

// Send NMF handshake
BOOL SendNMFHandshake(SOCKET socket, const char *target)
{
    BYTE *handshakeBuffer = NULL;
    BYTE *responseBuffer = NULL;
    int offset = 0;
    int ret;
    char viaString[256];
    int viaLen;
    BOOL success = FALSE;

    handshakeBuffer = (BYTE *)intAlloc(512);
    responseBuffer = (BYTE *)intAlloc(256);
    if (!handshakeBuffer || !responseBuffer)
    {
        goto cleanup;
    }

    MSVCRT$sprintf(viaString, "net.tcp://%s:9389/ActiveDirectoryWebServices/Windows/Enumeration", target);
    viaLen = MSVCRT$strlen(viaString);

    handshakeBuffer[offset++] = NMF_VERSION_RECORD;
    handshakeBuffer[offset++] = 0x01; // Major
    handshakeBuffer[offset++] = 0x00; // Minor

    handshakeBuffer[offset++] = NMF_MODE_RECORD;
    handshakeBuffer[offset++] = 0x02; // Duplex

    handshakeBuffer[offset++] = NMF_VIA_RECORD;
    handshakeBuffer[offset++] = (BYTE)viaLen;
    MSVCRT$memcpy(&handshakeBuffer[offset], viaString, viaLen);
    offset += viaLen;

    handshakeBuffer[offset++] = NMF_ENCODING_RECORD;
    handshakeBuffer[offset++] = 0x08; // NBFSE

    handshakeBuffer[offset++] = NMF_UPGRADE_REQUEST;
    handshakeBuffer[offset++] = 0x15; // Length
    MSVCRT$memcpy(&handshakeBuffer[offset], "application/negotiate", 0x15);
    offset += 0x15;

    ret = WS2_32$send(socket, (char *)handshakeBuffer, offset, 0);
    if (ret == SOCKET_ERROR)
    {
        goto cleanup;
    }

    ret = WS2_32$recv(socket, (char *)responseBuffer, 256, 0);
    if (ret <= 0 || responseBuffer[0] != NMF_UPGRADE_RESPONSE)
    {
        goto cleanup;
    }

    success = TRUE;

cleanup:
    if (handshakeBuffer)
        intFree(handshakeBuffer);
    if (responseBuffer)
        intFree(responseBuffer);
    return success;
}

// Unwrap NMF envelope to extract NBFSE payload
BOOL UnwrapNMFEnvelope(BYTE *nmfData, DWORD nmfLen, BYTE **nbfseData, DWORD *nbfseLen)
{
    DWORD offset = 0;

    if (nmfLen < 2 || nmfData[0] != NMF_SIZED_ENVELOPE)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[-] Not an NMF envelope (first byte: 0x%02X)", nmfLen > 0 ? nmfData[0] : 0);
        return FALSE;
    }
    offset++;

    DWORD payloadLen = 0;
    BYTE firstByte = nmfData[offset++];

    if ((firstByte & 0x80) == 0)
    {
        payloadLen = firstByte;
    }
    else
    {
        payloadLen = firstByte & 0x7F;
        int shift = 7;

        while (offset < nmfLen && shift < 32)
        {
            BYTE nextByte = nmfData[offset++];
            payloadLen |= (DWORD)(nextByte & 0x7F) << shift;

            if ((nextByte & 0x80) == 0)
            {
                break;
            }

            shift += 7;
        }
    }

    if (payloadLen > nmfLen - offset)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] NMF payload truncated: expected %d bytes, have %d bytes\n", payloadLen,
                     nmfLen - offset);

        *nbfseLen = nmfLen - offset;
        *nbfseData = (BYTE *)intAlloc(*nbfseLen);
        if (!*nbfseData)
            return FALSE;

        MSVCRT$memcpy(*nbfseData, nmfData + offset, *nbfseLen);
        return TRUE;
    }

    *nbfseData = (BYTE *)intAlloc(payloadLen);
    if (!*nbfseData)
        return FALSE;

    MSVCRT$memcpy(*nbfseData, nmfData + offset, payloadLen);
    *nbfseLen = payloadLen;

    return TRUE;
}

// Send ADWS message (wraps NBFSE in NMF envelope and sends via NNS)
BOOL SendADWSMessage(CONNECTION_CONTEXT *ctx, BYTE *nbfseMessage, DWORD nbfseLen)
{
    BYTE *nmfMessage = NULL;
    DWORD nmfLen;
    BOOL result = FALSE;

    // Build NMF envelope (0x06 + varint length + payload)
    BYTE varintBytes[5];
    DWORD varintLen = 0;

    // Encode length as varint
    if (nbfseLen < 0x80)
    {
        varintBytes[0] = (BYTE)nbfseLen;
        varintLen = 1;
    }
    else if (nbfseLen < 0x4000)
    {
        varintBytes[0] = (BYTE)(0x80 | (nbfseLen & 0x7F));
        varintBytes[1] = (BYTE)(nbfseLen >> 7);
        varintLen = 2;
    }
    else if (nbfseLen < 0x200000)
    {
        varintBytes[0] = (BYTE)(0x80 | (nbfseLen & 0x7F));
        varintBytes[1] = (BYTE)(0x80 | ((nbfseLen >> 7) & 0x7F));
        varintBytes[2] = (BYTE)(nbfseLen >> 14);
        varintLen = 3;
    }
    else if (nbfseLen < 0x10000000)
    {
        varintBytes[0] = (BYTE)(0x80 | (nbfseLen & 0x7F));
        varintBytes[1] = (BYTE)(0x80 | ((nbfseLen >> 7) & 0x7F));
        varintBytes[2] = (BYTE)(0x80 | ((nbfseLen >> 14) & 0x7F));
        varintBytes[3] = (BYTE)(nbfseLen >> 21);
        varintLen = 4;
    }
    else
    {
        varintBytes[0] = (BYTE)(0x80 | (nbfseLen & 0x7F));
        varintBytes[1] = (BYTE)(0x80 | ((nbfseLen >> 7) & 0x7F));
        varintBytes[2] = (BYTE)(0x80 | ((nbfseLen >> 14) & 0x7F));
        varintBytes[3] = (BYTE)(0x80 | ((nbfseLen >> 21) & 0x7F));
        varintBytes[4] = (BYTE)(nbfseLen >> 28);
        varintLen = 5;
    }

    // Allocate NMF message
    nmfLen = 1 + varintLen + nbfseLen;
    nmfMessage = (BYTE *)intAlloc(nmfLen);
    if (!nmfMessage)
        return FALSE;

    // Build NMF message
    nmfMessage[0] = NMF_SIZED_ENVELOPE;
    MSVCRT$memcpy(nmfMessage + 1, varintBytes, varintLen);
    MSVCRT$memcpy(nmfMessage + 1 + varintLen, nbfseMessage, nbfseLen);

    // Silent - sending NMF envelope
    // Send through encrypted channel
    result = NNSSendEncrypted(ctx, nmfMessage, nmfLen);

    intFree(nmfMessage);
    return result;
}

#endif
