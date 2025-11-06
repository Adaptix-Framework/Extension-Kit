/*
 * adws_parser.h - ADWS Response Parser
 *
 * Functions for parsing ADWS/NBFSE responses including:
 * - Enumerate/Pull response parsing
 * - Attribute extraction (text, numeric, binary, multi-value)
 * - Object boundary detection
 * - GUID and SID conversion
 * - Base64 encoding for binary data
 */

#ifndef ADWS_PARSER_H
#define ADWS_PARSER_H

#ifdef BOF
#include "beacon.h"
#include "bofdefs.h"
#else
#include <windows.h>
#endif

#ifdef BOF
typedef struct OUTPUT_BUFFER
{
    formatp buffer;
    BOOL initialized;
} OutputBuffer;
#else
typedef struct OUTPUT_BUFFER
{
    char *data;
    DWORD size;
    DWORD capacity;
} OutputBuffer;
#endif

void OutputInit(OutputBuffer *buf);
void OutputPrintf(OutputBuffer *buf, const char *format, ...);
void OutputFlush(OutputBuffer *buf, DWORD objIdx);
void internal_printf(const char *format, ...);
void printoutput(BOOL done);

typedef struct
{
    char name[64];
    char value[4096];
} ATTRIBUTE_ENTRY;

typedef struct
{
    DWORD start;
    DWORD end;
} OBJECT_BOUNDARY;

BOOL ParseEnumerateResponse(BYTE *response, DWORD responseLen, char *enumContext, DWORD contextSize);
BOOL ParsePullResponse(BYTE *response, DWORD responseLen, const char *attrFilter, BOOL *hasMore,
                       DWORD *objectsInThisPull);

char *ConvertBinaryToBase64(BYTE *data, DWORD len);
BOOL IsMetadata(const char *str);
BOOL ExtractAttributeUniversal(BYTE *data, DWORD len, const char *attributeName, char *outValue, DWORD outSize);
DWORD DiscoverAttributeNames(BYTE *data, DWORD start, DWORD end, char attributeNames[][64], DWORD maxAttrs);
DWORD DiscoverAttributesInObject(BYTE *data, DWORD start, DWORD end, ATTRIBUTE_ENTRY *attrs, DWORD maxAttrs);
DWORD FindObjectBoundaries(BYTE *data, DWORD dataLen, OBJECT_BOUNDARY *boundaries, DWORD maxBoundaries);

BOOL ParseEnumerateResponse(BYTE *response, DWORD responseLen, char *enumContext, DWORD contextSize)
{
    const char *contextTag = "EnumerationContext";
    DWORD i;

    // Look for EnumerationContext tag
    for (i = 0; i < responseLen - MSVCRT$strlen(contextTag); i++)
    {
        if (MSVCRT$memcmp(response + i, contextTag, MSVCRT$strlen(contextTag)) == 0)
        {
            i += MSVCRT$strlen(contextTag);

            while (i < responseLen && response[i] != 0x98 && response[i] != 0x99)
            {
                i++;
            }

            if (i < responseLen && (response[i] == 0x98 || response[i] == 0x99))
            {
                i++;
                BYTE textLen = response[i++];

                if (i + textLen <= responseLen)
                {
                    DWORD copyLen = (textLen < contextSize - 1) ? textLen : contextSize - 1;
                    MSVCRT$memcpy(enumContext, response + i, copyLen);
                    enumContext[copyLen] = '\0';
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

BOOL IsMetadata(const char *str)
{
    const char *metadata[] = {
        "xsd:string", "xsd:int", "xsd:long", "xsd:boolean", "xsd:dateTime", "xsd:base64Binary", "LdapSyntax",
        "UnicodeString", "DNString", "DSDNString", "SidString", "OctetString", "LargeInteger", "Integer", "Boolean",
        "GeneralizedTime", "DirectoryString", "DNWithBinary", "DNWithString", "ObjectIdentifier",
        "GeneralizedTimeString", "PrintableString", "UTF8String", "IA5String", "TimeString", "Identifier", "Syntax",
        "String",
        // XML namespace and SOAP metadata
        "objectReferenceProperty", "value", "xsi", "type", "ad", "addata", "wsen", "Items", "domainDNS", "xsd", NULL};

    // Check against known metadata
    for (int i = 0; metadata[i] != NULL; i++)
    {
        if (MSVCRT$strcmp(str, metadata[i]) == 0)
        {
            return TRUE;
        }
    }

    if (MSVCRT$strlen(str) == 36)
    {
        int dashCount = 0;
        for (int i = 0; i < 36; i++)
        {
            if (str[i] == '-')
                dashCount++;
        }
        if (dashCount == 4)
            return TRUE;
    }

    if (MSVCRT$strlen(str) == 1 && str[0] >= '0' && str[0] <= '9')
    {
        return TRUE;
    }

    return FALSE;
}

char *ConvertBinaryToBase64(BYTE *data, DWORD len)
{
    const char *b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DWORD outLen = ((len + 2) / 3) * 4 + 1;
    char *result = (char *)intAlloc(outLen);
    if (!result)
        return NULL;

    DWORD i, j;
    for (i = 0, j = 0; i < len; i += 3, j += 4)
    {
        DWORD n = (data[i] << 16) | ((i + 1 < len) ? (data[i + 1] << 8) : 0) | ((i + 2 < len) ? data[i + 2] : 0);
        result[j] = b64chars[(n >> 18) & 0x3F];
        result[j + 1] = b64chars[(n >> 12) & 0x3F];
        result[j + 2] = (i + 1 < len) ? b64chars[(n >> 6) & 0x3F] : '=';
        result[j + 3] = (i + 2 < len) ? b64chars[n & 0x3F] : '=';
    }
    result[j] = '\0';
    return result;
}

BOOL ExtractAttributeUniversal(BYTE *data, DWORD len, const char *attributeName, char *outValue, DWORD outSize)
{
    if (!data || !attributeName || !outValue || len == 0 || outSize == 0)
    {
        return FALSE;
    }

    outValue[0] = '\0';

    DWORD attrLen = MSVCRT$strlen(attributeName);

    // Check if this is a multi-value attribute
    BOOL isMultiValue =
        (MSVCRT$_stricmp(attributeName, "objectClass") == 0 ||
         MSVCRT$_stricmp(attributeName, "memberOf") == 0 ||
         MSVCRT$_stricmp(attributeName, "member") == 0 ||
         MSVCRT$_stricmp(attributeName, "dSCorePropagationData") == 0 ||
         MSVCRT$_stricmp(attributeName, "wellKnownObjects") == 0 ||
         MSVCRT$_stricmp(attributeName, "otherWellKnownObjects") == 0 ||
         MSVCRT$_stricmp(attributeName, "subRefs") == 0 ||
         MSVCRT$_stricmp(attributeName, "repsTo") == 0 ||
         MSVCRT$_stricmp(attributeName, "repsFrom") == 0 ||
         MSVCRT$_stricmp(attributeName, "masteredBy") == 0 ||
         MSVCRT$_stricmp(attributeName, "msDs-masteredBy") == 0 ||
         MSVCRT$_stricmp(attributeName, "servicePrincipalName") == 0 ||
         MSVCRT$_stricmp(attributeName, "msDS-IsDomainFor") == 0 ||
         MSVCRT$_stricmp(attributeName, "msDS-IsPartialReplicaFor") == 0);

    // Search for the attribute name
    for (DWORD i = 0; i < len - attrLen; i++)
    {
        BOOL match = FALSE;
        BOOL isAddataPattern = FALSE;

        // Pattern 1: Direct match (filtered responses) - attribute preceded by its length
        if (i > 0 && data[i - 1] == (BYTE)attrLen && i + attrLen + 2 < len)
        {
            BOOL looksLikeAttribute = FALSE;
            BYTE followingByte = data[i + attrLen];
            if (followingByte == 0x04 ||                            // Followed by a length byte
                followingByte == 0x41 ||                            // Followed by ELEMENT
                followingByte == 0x05 ||                            // Followed by another record
                (followingByte >= 0x80 && followingByte <= 0x86) || // Numeric value records
                (followingByte == 0x98 && data[i + attrLen + 1] == 0x0A))
            { // Text record "xsd:string"
                looksLikeAttribute = TRUE;
            }

            if (looksLikeAttribute)
            {
                match = TRUE;
                for (DWORD j = 0; j < attrLen; j++)
                {
                    if ((data[i + j] | 0x20) != (attributeName[j] | 0x20))
                    {
                        match = FALSE;
                        break;
                    }
                }
            }
        }

        // Pattern 2: addata.attributeName (unfiltered responses)
        if (!match && i >= 8 && attrLen > 0)
        {
            if (data[i - 8] == 0x41 && data[i - 7] == 0x06 && MSVCRT$memcmp(data + i - 6, "addata", 6) == 0 &&
                data[i - 1] == (BYTE)attrLen)
            {

                match = TRUE;
                for (DWORD j = 0; j < attrLen; j++)
                {
                    if ((data[i + j] | 0x20) != (attributeName[j] | 0x20))
                    {
                        match = FALSE;
                        break;
                    }
                }
                if (match)
                    isAddataPattern = TRUE;
            }
        }

        if (match)
        {
            // Skip past attribute name
            DWORD j = i + attrLen;

            // Skip metadata patterns
            const char *skipPatterns[] = {"xsd:string",
                                          "xsd:int",
                                          "xsd:long",
                                          "xsd:boolean",
                                          "xsd:dateTime",
                                          "xsd:base64Binary",
                                          "LdapSyntax",
                                          "UnicodeString",
                                          "DNString",
                                          "DSDNString",
                                          "SidString",
                                          "OctetString",
                                          "LargeInteger",
                                          "Integer",
                                          "Boolean",
                                          "GeneralizedTime",
                                          "DirectoryString",
                                          "DNWithBinary",
                                          "DNWithString",
                                          "ObjectIdentifier",
                                          "GeneralizedTimeString",
                                          "PrintableString",
                                          "UTF8String",
                                          "IA5String",
                                          "TimeString",
                                          "Identifier",
                                          "Syntax",
                                          "String",
                                          NULL};

            // Search for value - increase limits especially for multi-value
            DWORD maxSearch = isMultiValue ? 5000 : (isAddataPattern ? 500 : 300);
            DWORD searchLimit = (maxSearch < len - i - attrLen) ? maxSearch : (len - i - attrLen);

            while (j < len && j < i + attrLen + searchLimit)
            {

                while (j < len && data[j] == 0x00)
                    j++;

                if (j >= len)
                    break;

                BOOL isMetadata = FALSE;

                for (int p = 0; skipPatterns[p] != NULL; p++)
                {
                    DWORD patLen = MSVCRT$strlen(skipPatterns[p]);
                    if (j + patLen <= len)
                    {
                        if ((data[j] == 0x98 || data[j] == 0x99) && j + 1 < len)
                        {
                            BYTE tlen = data[j + 1];
                            if (tlen == patLen && j + 2 + tlen <= len &&
                                MSVCRT$memcmp(data + j + 2, skipPatterns[p], patLen) == 0)
                            {
                                j += 2 + tlen;
                                isMetadata = TRUE;
                                break;
                            }
                        }
                    }
                }

                if (isMetadata)
                {
                    continue;
                }

                // Look for actual value records
                BYTE recordType = data[j];

                if (recordType >= 0x80 && recordType <= 0x8F)
                {
                    if (isMultiValue)
                    {
                        j++;
                        continue;
                    }

                    if (recordType < 0x80 || recordType > 0x8F)
                    {
                        j++;
                        continue;
                    }

                    if (recordType == 0x80 || recordType == 0x81)
                    {
                        outValue[0] = '0';
                        outValue[1] = '\0';
                        return TRUE;
                    }
                    if (recordType == 0x82)
                    {
                        outValue[0] = '1';
                        outValue[1] = '\0';
                        return TRUE;
                    }

                    switch (recordType)
                    {
                    case 0x80:
                    case 0x81:
                        outValue[0] = '0';
                        outValue[1] = '\0';
                        return TRUE;
                    case 0x82:
                        outValue[0] = '1';
                        outValue[1] = '\0';
                        return TRUE;
                    case 0x83:
                        if (j + 1 < len)
                        {
                            MSVCRT$sprintf(outValue, "%d", (int)(signed char)data[j + 1]);
                            return TRUE;
                        }
                        break;
                    case 0x84:
                        if (j + 2 < len)
                        {
                            short val = data[j + 1] | (data[j + 2] << 8);
                            MSVCRT$sprintf(outValue, "%d", val);
                            return TRUE;
                        }
                        break;
                    case 0x85:
                        if (j + 4 < len)
                        {
                            int val = data[j + 1] | (data[j + 2] << 8) | (data[j + 3] << 16) | (data[j + 4] << 24);
                            MSVCRT$sprintf(outValue, "%d", val);
                            return TRUE;
                        }
                        break;
                    case 0x86:
                        if (j + 8 < len)
                        {
                            long long val = 0;
                            for (int k = 0; k < 8; k++)
                            {
                                val |= ((long long)data[j + 1 + k]) << (k * 8);
                            }
                            MSVCRT$sprintf(outValue, "%I64d", val);
                            return TRUE;
                        }
                        break;
                    default:
                        // For 0x87-0x8F, need length decoding
                        j++;
                        continue;
                    }
                }
                else if ((recordType == 0x98 || recordType == 0x99) && j + 1 < len)
                {
                    BYTE textLen = data[j + 1];
                    if (textLen > 0 && textLen < 250 && j + 2 + textLen <= len)
                    {
                        BOOL isValueMetadata = FALSE;
                        for (int p = 0; skipPatterns[p] != NULL; p++)
                        {
                            if (textLen == MSVCRT$strlen(skipPatterns[p]) &&
                                MSVCRT$memcmp(data + j + 2, skipPatterns[p], textLen) == 0)
                            {
                                isValueMetadata = TRUE;
                                break;
                            }
                        }

                        if (!isValueMetadata && textLen > 0)
                        {
                            if (MSVCRT$_stricmp(attributeName, "nTSecurityDescriptor") == 0)
                            {
                                // Skip text values for nTSecurityDescriptor
                                j += 2 + textLen;
                                continue;
                            }

                            if (isMultiValue && textLen == 1 && data[j + 2] >= '0' && data[j + 2] <= '9')
                            {
                                j += 2 + textLen;
                                continue;
                            }

                            if (isMultiValue)
                            {
                                BOOL isValidValue = TRUE;
                                char tempValue[256];
                                DWORD copyLen = (textLen < 255) ? textLen : 255;
                                MSVCRT$memcpy(tempValue, data + j + 2, copyLen);
                                tempValue[copyLen] = '\0';

                                if (MSVCRT$_stricmp(attributeName, "objectClass") == 0)
                                {
                                    BOOL hasAlpha = FALSE;
                                    for (DWORD k = 0; k < copyLen; k++)
                                    {
                                        if ((tempValue[k] >= 'a' && tempValue[k] <= 'z') ||
                                            (tempValue[k] >= 'A' && tempValue[k] <= 'Z'))
                                        {
                                            hasAlpha = TRUE;
                                        }
                                        else if (tempValue[k] != '-' && tempValue[k] != '_' &&
                                                 !(tempValue[k] >= '0' && tempValue[k] <= '9'))
                                        {
                                            isValidValue = FALSE;
                                            break;
                                        }
                                    }
                                    if (!hasAlpha)
                                        isValidValue = FALSE;
                                }
                                else if (MSVCRT$_stricmp(attributeName, "memberOf") == 0)
                                {
                                    if (!MSVCRT$strstr(tempValue, "CN=") && !MSVCRT$strstr(tempValue, "cn="))
                                    {
                                        isValidValue = FALSE;
                                    }
                                }
                                else if (MSVCRT$_stricmp(attributeName, "dSCorePropagationData") == 0)
                                {
                                    if (copyLen < 16 || tempValue[copyLen - 1] != 'Z' ||
                                        (copyLen > 2 && tempValue[copyLen - 3] != '.'))
                                    {
                                        isValidValue = FALSE;
                                    }
                                }
                                else if (MSVCRT$_stricmp(attributeName, "wellKnownObjects") == 0 ||
                                         MSVCRT$_stricmp(attributeName, "otherWellKnownObjects") == 0)
                                {
                                    if (copyLen < 5 || tempValue[0] != 'B' || tempValue[1] != ':')
                                    {
                                        isValidValue = FALSE;
                                    }
                                }

                                if (isValidValue)
                                {
                                    if (MSVCRT$strlen(outValue) > 0)
                                    {
                                        MSVCRT$strcat(outValue, ", ");
                                    }
                                    DWORD currentLen = MSVCRT$strlen(outValue);
                                    DWORD remainingSpace = outSize - currentLen - 1;
                                    if (copyLen > remainingSpace)
                                        copyLen = remainingSpace;
                                    MSVCRT$strncat(outValue, tempValue, copyLen);
                                }
                                j += 2 + textLen;
                                continue;
                            }
                            else
                            {
                                DWORD copyLen = (textLen < outSize - 1) ? textLen : outSize - 1;
                                MSVCRT$memcpy(outValue, data + j + 2, copyLen);
                                outValue[copyLen] = '\0';
                                return TRUE;
                            }
                        }
                    }
                }
                else if ((recordType == 0x9E || recordType == 0x9F) && j + 1 < len)
                {
                    BYTE binLen = data[j + 1];
                    if (binLen > 0 && j + 2 + binLen <= len)
                    {
                        if (MSVCRT$_stricmp(attributeName, "objectGUID") == 0)
                        {
                            BYTE guidBytes[16];
                            MSVCRT$memcpy(guidBytes, data + j + 2, binLen);

                            if (binLen == 15)
                            {
                                DWORD nextPos = j + 2 + binLen;
                                if (nextPos + 2 < len && data[nextPos] == 0x9F && data[nextPos + 1] == 0x01)
                                {
                                    guidBytes[15] = data[nextPos + 2];
                                }
                                else
                                {
                                    guidBytes[15] = 0;
                                }
                            }

                            MSVCRT$sprintf(
                                outValue, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                guidBytes[3], guidBytes[2], guidBytes[1], guidBytes[0], guidBytes[5], guidBytes[4],
                                guidBytes[7], guidBytes[6], guidBytes[8], guidBytes[9], guidBytes[10], guidBytes[11],
                                guidBytes[12], guidBytes[13], guidBytes[14], guidBytes[15]);
                            return TRUE;
                        }
                        else if (MSVCRT$_stricmp(attributeName, "objectSid") == 0 ||
                                 MSVCRT$_stricmp(attributeName, "objectsid") == 0)
                        {
                            BYTE sidBytes[68];
                            DWORD totalSidLen = binLen;
                            MSVCRT$memcpy(sidBytes, data + j + 2, binLen);

                            DWORD nextPos = j + 2 + binLen;
                            if (nextPos < len && data[nextPos] == 0x9F)
                            {
                                BYTE contLen = data[nextPos + 1];
                                if (nextPos + 2 + contLen <= len)
                                {
                                    MSVCRT$memcpy(sidBytes + binLen, data + nextPos + 2, contLen);
                                    totalSidLen = binLen + contLen;
                                }
                            }

                            if (totalSidLen > 8)
                            {
                                BYTE revision = sidBytes[0];
                                BYTE subAuthCount = sidBytes[1];
                                ULONGLONG authority = 0;
                                for (int k = 0; k < 6; k++)
                                {
                                    authority = (authority << 8) | sidBytes[2 + k];
                                }
                                char *p = outValue;
                                p += MSVCRT$sprintf(p, "S-%u-%llu", revision, authority);
                                for (BYTE k = 0; k < subAuthCount && (8 + k * 4 + 3) <= totalSidLen; k++)
                                {
                                    DWORD subAuth = sidBytes[8 + k * 4] | (sidBytes[8 + k * 4 + 1] << 8) |
                                                    (sidBytes[8 + k * 4 + 2] << 16) | (sidBytes[8 + k * 4 + 3] << 24);
                                    p += MSVCRT$sprintf(p, "-%lu", subAuth);
                                }
                                return TRUE;
                            }
                        }
                        else if (MSVCRT$_stricmp(attributeName, "securityIdentifier") == 0)
                        {
                            BYTE sidBytes[68];
                            DWORD totalSidLen = binLen;
                            MSVCRT$memcpy(sidBytes, data + j + 2, binLen);

                            DWORD nextPos = j + 2 + binLen;
                            if (nextPos < len && data[nextPos] == 0x9F)
                            {
                                BYTE contLen = data[nextPos + 1];
                                if (nextPos + 2 + contLen <= len)
                                {
                                    MSVCRT$memcpy(sidBytes + binLen, data + nextPos + 2, contLen);
                                    totalSidLen = binLen + contLen;
                                }
                            }

                            if (totalSidLen > 8)
                            {
                                BYTE revision = sidBytes[0];
                                BYTE subAuthCount = sidBytes[1];
                                ULONGLONG authority = 0;
                                for (int k = 0; k < 6; k++)
                                {
                                    authority = (authority << 8) | sidBytes[2 + k];
                                }
                                char *p = outValue;
                                p += MSVCRT$sprintf(p, "S-%u-%llu", revision, authority);
                                for (BYTE k = 0; k < subAuthCount && (8 + k * 4 + 3) <= totalSidLen; k++)
                                {
                                    DWORD subAuth = sidBytes[8 + k * 4] | (sidBytes[8 + k * 4 + 1] << 8) |
                                                    (sidBytes[8 + k * 4 + 2] << 16) | (sidBytes[8 + k * 4 + 3] << 24);
                                    p += MSVCRT$sprintf(p, "-%lu", subAuth);
                                }
                                return TRUE;
                            }
                        }
                        else
                        {
                            char *b64 = ConvertBinaryToBase64(data + j + 2, binLen);
                            if (b64)
                            {
                                MSVCRT$strncpy(outValue, b64, outSize - 1);
                                outValue[outSize - 1] = '\0';
                                intFree(b64);
                            }
                        }
                        return TRUE;
                    }
                }
                else if ((recordType == 0xA0 || recordType == 0xA1) && j + 2 < len)
                {
                    DWORD binLen = data[j + 1] | (data[j + 2] << 8);
                    if (binLen > 0 && j + 3 + binLen <= len)
                    {
                        BYTE *binData = data + j + 3;
                        DWORD totalLen = binLen;

                        DWORD nextOffset = j + 3 + binLen;
                        if (nextOffset < len && data[nextOffset] == 0x9F && nextOffset + 1 < len)
                        {
                            BYTE contLen = data[nextOffset + 1];
                            if (nextOffset + 2 + contLen <= len && contLen > 0)
                            {
                                BYTE *combined = (BYTE *)intAlloc(binLen + contLen);
                                if (combined)
                                {
                                    MSVCRT$memcpy(combined, binData, binLen);
                                    MSVCRT$memcpy(combined + binLen, data + nextOffset + 2, contLen);
                                    binData = combined;
                                    totalLen = binLen + contLen;
                                }
                            }
                        }

                        char *b64 = ConvertBinaryToBase64(binData, totalLen);
                        if (b64)
                        {
                            MSVCRT$strncpy(outValue, b64, outSize - 1);
                            outValue[outSize - 1] = '\0';
                            intFree(b64);
                        }

                        if (binData != data + j + 3)
                        {
                            intFree((void *)binData);
                        }

                        return TRUE;
                    }
                }
                else if (recordType == 0x01)
                {
                    break;
                }

                j++;
            }

            // For multi-value attributes, return whats collected if found any values
            if (isMultiValue && MSVCRT$strlen(outValue) > 0)
            {
                return TRUE;
            }

            return FALSE;
        }
    }

    return FALSE;
}

DWORD DiscoverAttributeNames(BYTE *data, DWORD start, DWORD end, char attributeNames[][64], DWORD maxAttrs)
{
    DWORD attrCount = 0;

    const char *skipMetadata[] = {
        "wsen", "Items", "domainDNS", "objectReferenceProperty", "value", "xsi", "type", "LdapSyntax", "DSDNString",
        "Integer", "LargeInteger", "GeneralizedTimeString", "UnicodeString", "Boolean", "ObjectIdentifier", "top",
        "leaf", "domain", "DNBinary", "ReplicaLink", "OctetString", "SidString", "addata", "Syntax", "String",
        "DirectoryString", "DNString", "DNWithBinary", "DNWithString", "PrintableString", "UTF8String", "IA5String",
        "TimeString", "Identifier",
        // Object type markers - these are XML element names, not attributes
        "user", "group", "computer", "organizationalUnit", "container",
        // Common objectClass values that might be picked up as attributes
        "person", "organizationalPerson", "inetOrgPerson", "contact", "msDS-GroupManagedServiceAccount",
        "msDS-ManagedServiceAccount", "trustedDomain", "foreignSecurityPrincipal", "device",
        // Other metadata that might appear
        "container-hierarchy-parent", "relativeDistinguishedName", "ad", "xsd", "instance", NULL};

    // Scan for addata.attributeName patterns
    for (DWORD i = start; i < end - 10 && attrCount < maxAttrs; i++)
    {
        if (data[i] == 0x41 && data[i + 1] == 0x06 && i + 8 < end && MSVCRT$memcmp(data + i + 2, "addata", 6) == 0)
        {

            BYTE attrLen = data[i + 8];
            if (attrLen > 0 && attrLen < 64 && i + 9 + attrLen <= end)
            {
                // Extract attribute name
                char attrName[64];
                MSVCRT$memcpy(attrName, data + i + 9, attrLen);
                attrName[attrLen] = '\0';

                // Check if it's a valid attribute name (not metadata)
                BOOL isValid = TRUE;
                BOOL hasAlpha = FALSE;
                for (BYTE j = 0; j < attrLen; j++)
                {
                    if ((attrName[j] >= 'a' && attrName[j] <= 'z') || (attrName[j] >= 'A' && attrName[j] <= 'Z'))
                    {
                        hasAlpha = TRUE;
                    }
                    else if (attrName[j] != '-' && attrName[j] != '_' && !(attrName[j] >= '0' && attrName[j] <= '9'))
                    {
                        isValid = FALSE;
                        break;
                    }
                }

                // Skip metadata strings
                if (isValid && hasAlpha)
                {
                    for (int m = 0; skipMetadata[m] != NULL; m++)
                    {
                        if (MSVCRT$_stricmp(attrName, skipMetadata[m]) == 0)
                        {
                            isValid = FALSE;
                            break;
                        }
                    }
                }

                if (isValid && hasAlpha)
                {
                    BOOL isDuplicate = FALSE;
                    for (DWORD j = 0; j < attrCount; j++)
                    {
                        if (MSVCRT$_stricmp(attributeNames[j], attrName) == 0)
                        {
                            isDuplicate = TRUE;
                            break;
                        }
                    }

                    if (!isDuplicate && attrCount < maxAttrs)
                    {
                        MSVCRT$strcpy(attributeNames[attrCount], attrName);
                        attrCount++;
                    }
                }
            }
        }

        // Also look for direct attribute patterns (filtered responses)
        // Pattern: <attrLen> <attributeName> followed by specific markers
        if (i > 0 && data[i - 1] > 0 && data[i - 1] < 64)
        {
            BYTE possibleAttrLen = data[i - 1];
            if (i + possibleAttrLen + 1 < end)
            {
                // Check if followed by known markers
                BYTE followingByte = data[i + possibleAttrLen];
                if (followingByte == 0x04 || followingByte == 0x41 || followingByte == 0x05 || followingByte == 0x98 ||
                    (followingByte >= 0x80 && followingByte <= 0x86))
                {

                    // Extract potential attribute name
                    char attrName[64];
                    BOOL isValid = TRUE;
                    BOOL hasAlpha = FALSE;

                    // Must start at valid position and contain valid chars
                    if (i + possibleAttrLen > end)
                    {
                        continue;
                    }

                    for (BYTE j = 0; j < possibleAttrLen; j++)
                    {
                        attrName[j] = data[i + j];
                        if ((attrName[j] >= 'a' && attrName[j] <= 'z') || (attrName[j] >= 'A' && attrName[j] <= 'Z'))
                        {
                            hasAlpha = TRUE;
                        }
                        else if (attrName[j] != '-' && attrName[j] != '_' &&
                                 !(attrName[j] >= '0' && attrName[j] <= '9'))
                        {
                            isValid = FALSE;
                            break;
                        }
                    }
                    attrName[possibleAttrLen] = '\0';

                    if (isValid && hasAlpha && MSVCRT$strlen(attrName) > 2)
                    {
                        // Skip metadata strings
                        for (int m = 0; skipMetadata[m] != NULL; m++)
                        {
                            if (MSVCRT$_stricmp(attrName, skipMetadata[m]) == 0)
                            {
                                isValid = FALSE;
                                break;
                            }
                        }

                        if (isValid)
                        {
                            // Check if we already have this attribute
                            BOOL isDuplicate = FALSE;
                            for (DWORD j = 0; j < attrCount; j++)
                            {
                                if (MSVCRT$_stricmp(attributeNames[j], attrName) == 0)
                                {
                                    isDuplicate = TRUE;
                                    break;
                                }
                            }

                            if (!isDuplicate)
                            {
                                MSVCRT$strcpy(attributeNames[attrCount], attrName);
                                attrCount++;
                            }
                        }
                    }
                }
            }
        }
    }

    // Also check for direct attribute patterns (length-prefixed)
    for (DWORD i = start + 1; i < end - 5 && attrCount < maxAttrs; i++)
    {
        BYTE possibleLen = data[i - 1];
        if (possibleLen > 0 && possibleLen < 64 && i + possibleLen + 2 < end)
        {
            if (data[i + possibleLen] == 0x04 || data[i + possibleLen] == 0x41 || data[i + possibleLen] == 0x05 ||
                (data[i + possibleLen] == 0x98 && data[i + possibleLen + 1] == 0x0A) ||
                (data[i + possibleLen] >= 0x80 && data[i + possibleLen] <= 0x86))
            {

                char attrName[64];
                MSVCRT$memcpy(attrName, data + i, possibleLen);
                attrName[possibleLen] = '\0';

                BOOL isValid = TRUE;
                BOOL hasAlpha = FALSE;
                for (BYTE j = 0; j < possibleLen; j++)
                {
                    if ((attrName[j] >= 'a' && attrName[j] <= 'z') || (attrName[j] >= 'A' && attrName[j] <= 'Z'))
                    {
                        hasAlpha = TRUE;
                    }
                    else if (attrName[j] != '-' && attrName[j] != '_' && !(attrName[j] >= '0' && attrName[j] <= '9'))
                    {
                        isValid = FALSE;
                        break;
                    }
                }

                if (isValid && hasAlpha)
                {
                    for (int m = 0; skipMetadata[m] != NULL; m++)
                    {
                        if (MSVCRT$_stricmp(attrName, skipMetadata[m]) == 0)
                        {
                            isValid = FALSE;
                            break;
                        }
                    }

                    if (isValid)
                    {
                        BOOL isDuplicate = FALSE;
                        for (DWORD j = 0; j < attrCount; j++)
                        {
                            if (MSVCRT$_stricmp(attributeNames[j], attrName) == 0)
                            {
                                isDuplicate = TRUE;
                                break;
                            }
                        }

                        if (!isDuplicate && attrCount < maxAttrs)
                        {
                            MSVCRT$strcpy(attributeNames[attrCount], attrName);
                            attrCount++;
                        }
                    }
                }
            }
        }
    }

    return attrCount;
}

DWORD DiscoverAttributesInObject(BYTE *data, DWORD start, DWORD end, ATTRIBUTE_ENTRY *attrs, DWORD maxAttrs)
{
    DWORD attrCount = 0;

    char (*attributeNames)[64] = (char (*)[64])intAlloc(200 * 64);
    if (!attributeNames)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for attribute names");
        return 0;
    }

    // Discover from object boundaries
    DWORD nameCount = DiscoverAttributeNames(data, start, end, attributeNames, 200);

    // Extract value for each discovered attribute
    for (DWORD i = 0; i < nameCount && attrCount < maxAttrs; i++)
    {
        if (attrCount >= maxAttrs)
            break;

        // Clear the entry first - ensure full initialization
        MSVCRT$memset(&attrs[attrCount], 0, sizeof(ATTRIBUTE_ENTRY));

        // Copy the attribute name
        MSVCRT$strcpy(attrs[attrCount].name, attributeNames[i]);

        // Use universal extractor to get the value - search within object boundaries
        if (data && start < end && attributeNames[i][0] != '\0')
        {
            if (ExtractAttributeUniversal(data + start, end - start, attributeNames[i], attrs[attrCount].value,
                                          sizeof(attrs[attrCount].value)))
            {
                attrCount++;
            }
        }
    }

    intFree(attributeNames);
    return attrCount;
}

// First tries explicit type markers (addata:user, addata:computer, etc.)
// Falls back to DN-based detection for objects without type markers (like trustedDomain)
DWORD FindObjectBoundaries(BYTE *data, DWORD dataLen, OBJECT_BOUNDARY *boundaries, DWORD maxBoundaries)
{
    DWORD boundaryCount = 0;
    DWORD *objectStarts = (DWORD *)intAlloc(5000 * sizeof(DWORD));
    if (!objectStarts)
        return 0;
    DWORD objectStartCount = 0;

    for (DWORD i = 0; i < dataLen - 20; i++)
    {
        if (i + 6 < dataLen && MSVCRT$memcmp(data + i, "addata", 6) == 0)
        {
            BYTE lenByte = data[i + 6];

            if (lenByte == 0x04 && i + 11 < dataLen && MSVCRT$memcmp(data + i + 7, "user", 4) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x08 && i + 15 < dataLen && MSVCRT$memcmp(data + i + 7, "computer", 8) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x05 && i + 12 < dataLen && MSVCRT$memcmp(data + i + 7, "group", 5) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x06 && i + 13 < dataLen && MSVCRT$memcmp(data + i + 7, "domain", 6) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x09 && i + 16 < dataLen && MSVCRT$memcmp(data + i + 7, "domainDNS", 9) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x09 && i + 16 < dataLen && MSVCRT$memcmp(data + i + 7, "container", 9) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x12 && i + 25 < dataLen && MSVCRT$memcmp(data + i + 7, "organizationalUnit", 18) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x07 && i + 14 < dataLen && MSVCRT$memcmp(data + i + 7, "dnsNode", 7) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x06 && i + 13 < dataLen && MSVCRT$memcmp(data + i + 7, "msDFSR", 6) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x18 && i + 31 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "foreignSecurityPrincipal", 24) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x14 && i + 27 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "groupPolicyContainer", 20) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x09 && i + 16 < dataLen && MSVCRT$memcmp(data + i + 7, "msImaging", 9) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0C && i + 19 < dataLen && MSVCRT$memcmp(data + i + 7, "lostAndFound", 12) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x14 && i + 27 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "infrastructureUpdate", 20) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0D && i + 20 < dataLen && MSVCRT$memcmp(data + i + 7, "builtinDomain", 13) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0D && i + 20 < dataLen && MSVCRT$memcmp(data + i + 7, "trustedDomain", 13) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0C && i + 19 < dataLen && MSVCRT$memcmp(data + i + 7, "rpcContainer", 12) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x07 && i + 14 < dataLen && MSVCRT$memcmp(data + i + 7, "dnsZone", 7) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x07 && i + 14 < dataLen && MSVCRT$memcmp(data + i + 7, "dnsNode", 7) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x09 && i + 16 < dataLen && MSVCRT$memcmp(data + i + 7, "samServer", 9) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0A && i + 17 < dataLen && MSVCRT$memcmp(data + i + 7, "rIDManager", 10) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x06 && i + 13 < dataLen && MSVCRT$memcmp(data + i + 7, "rIDSet", 6) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x10 && i + 23 < dataLen && MSVCRT$memcmp(data + i + 7, "fileLinkTracking", 16) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x18 && i + 31 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "linkTrackObjectMoveTable", 24) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0C && i + 19 < dataLen && MSVCRT$memcmp(data + i + 7, "domainPolicy", 12) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0A && i + 17 < dataLen && MSVCRT$memcmp(data + i + 7, "classStore", 10) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x14 && i + 27 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "infrastructureUpdate", 20) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0D && i + 20 < dataLen && MSVCRT$memcmp(data + i + 7, "nTFRSSettings", 13) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x14 && i + 27 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDFSR-LocalSettings", 20) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x11 && i + 24 < dataLen && MSVCRT$memcmp(data + i + 7, "msDFSR-Subscriber", 17) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x13 && i + 26 < dataLen && MSVCRT$memcmp(data + i + 7, "msDFSR-Subscription", 19) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x15 && i + 28 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDFSR-GlobalSettings", 21) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x17 && i + 30 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDFSR-ReplicationGroup", 23) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0E && i + 21 < dataLen && MSVCRT$memcmp(data + i + 7, "msDFSR-Content", 14) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x11 && i + 24 < dataLen && MSVCRT$memcmp(data + i + 7, "msDFSR-ContentSet", 17) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0F && i + 22 < dataLen && MSVCRT$memcmp(data + i + 7, "msDFSR-Topology", 15) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0D && i + 20 < dataLen && MSVCRT$memcmp(data + i + 7, "msDFSR-Member", 13) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x10 && i + 23 < dataLen && MSVCRT$memcmp(data + i + 7, "dfsConfiguration", 16) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0E && i + 21 < dataLen && MSVCRT$memcmp(data + i + 7, "msImaging-PSPs", 14) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x07 && i + 14 < dataLen && MSVCRT$memcmp(data + i + 7, "contact", 7) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x20 && i + 39 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDS-GroupManagedServiceAccount", 32) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x1B && i + 34 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDS-ManagedServiceAccount", 27) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0B && i + 18 < dataLen && MSVCRT$memcmp(data + i + 7, "msDS-Device", 11) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x15 && i + 28 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDS-PasswordSettings", 21) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x04 && i + 11 < dataLen && MSVCRT$memcmp(data + i + 7, "site", 4) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x06 && i + 13 < dataLen && MSVCRT$memcmp(data + i + 7, "subnet", 6) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x08 && i + 15 < dataLen && MSVCRT$memcmp(data + i + 7, "siteLink", 8) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0E && i + 21 < dataLen && MSVCRT$memcmp(data + i + 7, "siteLinkBridge", 14) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x07 && i + 14 < dataLen && MSVCRT$memcmp(data + i + 7, "nTDSDSA", 7) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x06 && i + 13 < dataLen && MSVCRT$memcmp(data + i + 7, "server", 6) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0E && i + 21 < dataLen && MSVCRT$memcmp(data + i + 7, "nTDSConnection", 14) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x14 && i + 27 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "pKIEnrollmentService", 20) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x16 && i + 29 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "pKICertificateTemplate", 22) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x16 && i + 29 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "certificationAuthority", 22) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x14 && i + 27 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "cRLDistributionPoint", 20) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x13 && i + 26 < dataLen && MSVCRT$memcmp(data + i + 7, "pKIKeyRecoveryAgent", 19) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x08 && i + 15 < dataLen && MSVCRT$memcmp(data + i + 7, "crossRef", 8) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0B && i + 18 < dataLen && MSVCRT$memcmp(data + i + 7, "queryPolicy", 11) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x13 && i + 26 < dataLen && MSVCRT$memcmp(data + i + 7, "msDS-QuotaContainer", 19) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x11 && i + 24 < dataLen && MSVCRT$memcmp(data + i + 7, "msDS-QuotaControl", 17) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0B && i + 18 < dataLen && MSVCRT$memcmp(data + i + 7, "classSchema", 11) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0F && i + 22 < dataLen && MSVCRT$memcmp(data + i + 7, "attributeSchema", 15) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x09 && i + 16 < dataLen && MSVCRT$memcmp(data + i + 7, "subSchema", 9) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x16 && i + 29 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "serviceConnectionPoint", 22) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x11 && i + 24 < dataLen && MSVCRT$memcmp(data + i + 7, "msSFU30DomainInfo", 17) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0A && i + 17 < dataLen && MSVCRT$memcmp(data + i + 7, "printQueue", 10) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x06 && i + 13 < dataLen && MSVCRT$memcmp(data + i + 7, "volume", 6) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0F && i + 22 < dataLen && MSVCRT$memcmp(data + i + 7, "connectionPoint", 15) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0D && i + 20 < dataLen && MSVCRT$memcmp(data + i + 7, "dynamicObject", 13) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0D && i + 20 < dataLen && MSVCRT$memcmp(data + i + 7, "inetOrgPerson", 13) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0E && i + 21 < dataLen && MSVCRT$memcmp(data + i + 7, "msDS-ClaimType", 14) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x15 && i + 28 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDS-ResourceProperty", 21) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x18 && i + 31 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDS-CentralAccessPolicy", 24) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x10 && i + 23 < dataLen && MSVCRT$memcmp(data + i + 7, "nTDSSiteSettings", 16) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x09 && i + 16 < dataLen && MSVCRT$memcmp(data + i + 7, "samDomain", 9) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x13 && i + 26 < dataLen && MSVCRT$memcmp(data + i + 7, "msDS-AzAdminManager", 19) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x13 && i + 26 < dataLen && MSVCRT$memcmp(data + i + 7, "msExchSystemMailbox", 19) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x12 && i + 25 < dataLen && MSVCRT$memcmp(data + i + 7, "msExchPublicFolder", 18) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x1E && i + 37 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msExchDynamicDistributionList", 30) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x14 && i + 27 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "organizationalPerson", 20) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x06 && i + 13 < dataLen && MSVCRT$memcmp(data + i + 7, "person", 6) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x1E && i + 37 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msTPM-TpmInformationForComputer", 31) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x1B && i + 34 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msFVE-RecoveryInformation", 25) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x13 && i + 26 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDS-KeyCredentialLink", 22) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x16 && i + 29 < dataLen &&
                     MSVCRT$memcmp(data + i + 7, "msDS-AuthNPolicySilo", 20) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x1A && i + 33 < dataLen && MSVCRT$memcmp(data + i + 7, "msDS-AuthNPolicy", 16) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0B && i + 18 < dataLen && MSVCRT$memcmp(data + i + 7, "printServer", 11) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0D && i + 20 < dataLen && MSVCRT$memcmp(data + i + 7, "configuration", 13) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x10 && i + 23 < dataLen && MSVCRT$memcmp(data + i + 7, "displaySpecifier", 16) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x12 && i + 25 < dataLen && MSVCRT$memcmp(data + i + 7, "interSiteTransport", 18) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x13 && i + 26 < dataLen && MSVCRT$memcmp(data + i + 7, "applicationSettings", 19) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x13 && i + 26 < dataLen && MSVCRT$memcmp(data + i + 7, "packageRegistration", 19) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x03 && i + 10 < dataLen && MSVCRT$memcmp(data + i + 7, "top", 3) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x0E && i + 21 < dataLen && MSVCRT$memcmp(data + i + 7, "securityObject", 14) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
            else if (lenByte == 0x11 && i + 24 < dataLen && MSVCRT$memcmp(data + i + 7, "applicationEntity", 17) == 0)
            {
                if (objectStartCount < 5000)
                {
                    objectStarts[objectStartCount++] = i;
                }
            }
        }
    }

    if (objectStartCount == 0)
    {
        typedef struct
        {
            DWORD offset;
            char dn[256];
            BOOL isObjectDN;
        } DNInfo;

        DNInfo *dnInfos = (DNInfo *)intAlloc(sizeof(DNInfo) * 5000);
        if (!dnInfos)
        {
            intFree(objectStarts);
            return 0;
        }
        DWORD dnCount = 0;

        for (DWORD i = 0; i < dataLen - 20; i++)
        {
            if ((data[i] == 0x98 || data[i] == 0x99) && i + 1 < dataLen)
            {
                BYTE textLen = data[i + 1];
                if (textLen > 10 && textLen < 250 && i + 2 + textLen <= dataLen)
                {
                    char textValue[256];
                    MSVCRT$memcpy(textValue, data + i + 2, textLen);
                    textValue[textLen] = '\0';

                    // Check if this could be a DN
                    if ((MSVCRT$strstr(textValue, "CN=") || MSVCRT$strstr(textValue, "cn=")) ||
                        (MSVCRT$strstr(textValue, "DC=") || MSVCRT$strstr(textValue, "dc=")) ||
                        (MSVCRT$strstr(textValue, "OU=") || MSVCRT$strstr(textValue, "ou=")))
                    {

                        BOOL isDN = FALSE;
                        DWORD dnAttrOffset = 0;
                        for (DWORD k = (i > 200) ? i - 200 : 0; k < i; k++)
                        {
                            if (k + 17 < i && MSVCRT$memcmp(data + k, "distinguishedName", 17) == 0)
                            {
                                BOOL hasIntermediateDN = FALSE;
                                for (DWORD m = k + 17; m < i; m++)
                                {
                                    if ((data[m] == 0x98 || data[m] == 0x99) && m + 1 < dataLen)
                                    {
                                        BYTE len = data[m + 1];
                                        if (len > 10 && len < 200 && m + 2 + len <= dataLen)
                                        {
                                            char val[256];
                                            MSVCRT$memcpy(val, data + m + 2, len);
                                            val[len] = '\0';
                                            if (MSVCRT$strstr(val, "DC=") || MSVCRT$strstr(val, "CN=") ||
                                                MSVCRT$strstr(val, "OU="))
                                            {
                                                hasIntermediateDN = TRUE;
                                                break;
                                            }
                                        }
                                    }
                                }
                                if (!hasIntermediateDN)
                                {
                                    isDN = TRUE;
                                    dnAttrOffset = k;
                                    break;
                                }
                            }
                        }

                        if (isDN && dnCount < 5000)
                        {
                            BOOL isDuplicate = FALSE;
                            for (DWORD j = 0; j < dnCount; j++)
                            {
                                if (MSVCRT$strcmp(dnInfos[j].dn, textValue) == 0)
                                {
                                    isDuplicate = TRUE;
                                    break;
                                }
                            }

                            if (!isDuplicate)
                            {
                                dnInfos[dnCount].offset = i;
                                MSVCRT$strcpy(dnInfos[dnCount].dn, textValue);
                                dnInfos[dnCount].isObjectDN = TRUE;
                                dnCount++;
                            }
                        }
                    }
                }
            }
        }

        for (DWORD i = 0; i < dnCount; i++)
        {
            if (dnInfos[i].isObjectDN && objectStartCount < 5000)
            {
                DWORD objectStart = dnInfos[i].offset;

                DWORD searchStart = (dnInfos[i].offset > 2000) ? dnInfos[i].offset - 2000 : 0;

                if (i > 0)
                {
                    DWORD prevDNOffset = dnInfos[i - 1].offset;
                    if (searchStart < prevDNOffset)
                    {
                        searchStart = prevDNOffset + 100;
                    }
                }

                BOOL foundStart = FALSE;
                for (DWORD k = dnInfos[i].offset; k > searchStart; k--)
                {
                    if (data[k] == 0x01)
                    {
                        BOOL foundObjectMarker = FALSE;
                        for (DWORD m = k; m < k + 200 && m < dnInfos[i].offset; m++)
                        {
                            if ((m + 11 < dataLen && MSVCRT$memcmp(data + m, "objectClass", 11) == 0))
                            {
                                foundObjectMarker = TRUE;
                                objectStart = k + 1;
                                foundStart = TRUE;
                                break;
                            }
                        }
                        if (foundObjectMarker)
                            break;
                    }
                }

                if (!foundStart)
                {
                    objectStart = searchStart;
                }

                objectStarts[objectStartCount++] = objectStart;
            }
        }

        intFree(dnInfos);
    }

    // Sort object starts to ensure they're in order
    for (DWORD i = 0; i < objectStartCount - 1; i++)
    {
        for (DWORD j = i + 1; j < objectStartCount; j++)
        {
            if (objectStarts[i] > objectStarts[j])
            {
                DWORD temp = objectStarts[i];
                objectStarts[i] = objectStarts[j];
                objectStarts[j] = temp;
            }
        }
    }

    // Create boundaries for each object
    for (DWORD i = 0; i < objectStartCount && boundaryCount < maxBoundaries; i++)
    {
        boundaries[boundaryCount].start = objectStarts[i];

        // Set end to next object start or data end
        if (i + 1 < objectStartCount)
        {
            boundaries[boundaryCount].end = objectStarts[i + 1];
        }
        else
        {
            boundaries[boundaryCount].end = dataLen;
        }

        boundaryCount++;
    }

    intFree(objectStarts);
    return boundaryCount;
}

BOOL ParsePullResponse(BYTE *response, DWORD responseLen, const char *attrFilter, BOOL *hasMore,
                       DWORD *objectsInThisPull)
{
    static DWORD totalObjectCount = 0;
    DWORD objectCount = 0;

    *hasMore = TRUE;

    // Look for EndOfSequence marker patterns
    const char *endSeqPatterns[] = {
        "\x01\x0B\x0F"
        "EndOfSequence", // 13 bytes
        "\x01\x01\x0B\x0F"
        "EndOfSequence", // 14 bytes
        "\x01\x01\x01\x0B\x0F"
        "EndOfSequence" // 23 bytes (extra 0x01s seen in some responses)
    };

    BOOL foundEndOfSequence = FALSE;
    for (int p = 0; p < 3; p++)
    {
        const char *pattern = endSeqPatterns[p];
        DWORD patLen = (p == 0) ? 13 : (p == 1) ? 14 : 23;

        // Only search in the last portion of the response
        DWORD searchStart = (responseLen > 1000) ? responseLen - 1000 : 0;

        for (DWORD i = searchStart; i + patLen <= responseLen; i++)
        {
            if (MSVCRT$memcmp(response + i, pattern, patLen) == 0)
            {
                *hasMore = FALSE;
                foundEndOfSequence = TRUE;
                break;
            }
        }
        if (foundEndOfSequence)
            break;
    }

    // Find object boundaries
    OBJECT_BOUNDARY *boundaries = (OBJECT_BOUNDARY *)intAlloc(sizeof(OBJECT_BOUNDARY) * 5000);
    if (!boundaries)
        return FALSE;

    DWORD boundaryCount = FindObjectBoundaries(response, responseLen, boundaries, 5000);
    objectCount = boundaryCount;
    totalObjectCount += objectCount;

    if (objectCount == 0)
    {
        // No objects found - check response size to determine if its done
        if (responseLen < 600)
        {
            // Small response with no objects indicates end
            *hasMore = FALSE;
            BeaconPrintf(CALLBACK_OUTPUT, "[*] No more objects (empty response of %d bytes)", responseLen);
        }
        else
        {
            // Large response with no objects might be an error
            BeaconPrintf(CALLBACK_OUTPUT, "[!] No objects found in large response (%d bytes) - may be parsing error",
                         responseLen);
        }
        intFree(boundaries);
        return TRUE;
    }

    if (totalObjectCount == objectCount)
    {
        internal_printf("Results:\n\n");
        printoutput(FALSE);
    }

    // Parse each object
    for (DWORD objIdx = 0; objIdx < boundaryCount; objIdx++)
    {
        // Create a temporary buffer for an object
        OutputBuffer outBuf;
        OutputInit(&outBuf);

        OutputPrintf(&outBuf, "--------------------\n");

        // Find the DN for this object by looking within its boundaries
        char objectDN[256] = {0};
        DWORD searchStart = boundaries[objIdx].start;
        DWORD searchEnd = boundaries[objIdx].end;

        // Validate boundaries
        if (searchStart >= responseLen || searchEnd > responseLen || searchStart >= searchEnd)
        {
            OutputPrintf(&outBuf, "\n[ERROR] Invalid boundaries for object %d: start=%d, end=%d, responseLen=%d",
                         objIdx, searchStart, searchEnd, responseLen);
            OutputFlush(&outBuf, objIdx);
            continue;
        }

        for (DWORD i = searchStart; i < searchEnd && i < responseLen - 20; i++)
        {
            if ((response[i] == 0x98 || response[i] == 0x99) && i + 1 < responseLen)
            {
                BYTE textLen = response[i + 1];
                if (textLen > 10 && textLen < 200 && i + 2 + textLen <= responseLen)
                {
                    char textValue[256];
                    MSVCRT$memcpy(textValue, response + i + 2, textLen);
                    textValue[textLen] = '\0';

                    if ((MSVCRT$strstr(textValue, "CN=") || MSVCRT$strstr(textValue, "cn=")) &&
                        (MSVCRT$strstr(textValue, "DC=") || MSVCRT$strstr(textValue, "dc=")))
                    {
                        BOOL isDN = FALSE;
                        for (DWORD k = (i > 200) ? i - 200 : searchStart; k < i; k++)
                        {
                            if (k + 17 < i && MSVCRT$memcmp(response + k, "distinguishedName", 17) == 0)
                            {
                                isDN = TRUE;
                                break;
                            }
                        }
                        if (isDN)
                        {
                            MSVCRT$strcpy(objectDN, textValue);
                            break;
                        }
                    }
                }
            }
        }

        // Parse attribute filter if provided
        if (attrFilter && MSVCRT$strlen(attrFilter) > 0)
        {
            ATTRIBUTE_ENTRY *attrs = (ATTRIBUTE_ENTRY *)intAlloc(sizeof(ATTRIBUTE_ENTRY) * 200);
            if (!attrs)
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for attributes");
                continue;
            }

            DWORD attrCount =
                DiscoverAttributesInObject(response, boundaries[objIdx].start, boundaries[objIdx].end, attrs, 200);

            if (attrCount > 0)
            {
                // Split comma-separated attribute names
                char filterCopy[256];
                MSVCRT$strncpy(filterCopy, attrFilter, 255);
                filterCopy[255] = '\0';

                char *filterAttrs[50];
                DWORD filterCount = 0;
                char *token = MSVCRT$strtok(filterCopy, ",");

                while (token != NULL && filterCount < 50)
                {
                    while (*token == ' ')
                        token++;
                    filterAttrs[filterCount++] = token;
                    token = MSVCRT$strtok(NULL, ",");
                }

                // Display only filtered attributes
                for (DWORD f = 0; f < filterCount; f++)
                {
                    for (DWORD i = 0; i < attrCount; i++)
                    {
                        if (MSVCRT$_stricmp(attrs[i].name, filterAttrs[f]) == 0)
                        {
                            OutputPrintf(&outBuf, "%s: %s\n", attrs[i].name, attrs[i].value);
                            break;
                        }
                    }
                }
            }

            intFree(attrs);
        }
        else
        {
            char (*attributeNames)[64] = (char (*)[64])intAlloc(200 * 64);
            if (!attributeNames)
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for attribute names");
                continue;
            }

            DWORD nameCount =
                DiscoverAttributeNames(response, boundaries[objIdx].start, boundaries[objIdx].end, attributeNames, 200);

            if (nameCount > 0)
            {
                char *attrValue = (char *)intAlloc(4096);
                if (!attrValue)
                {
                    BeaconPrintf(CALLBACK_ERROR, "[-] Failed to allocate memory for attribute value");
                    intFree(attributeNames);
                    continue;
                }

                for (DWORD i = 0; i < nameCount; i++)
                {
                    MSVCRT$memset(attrValue, 0, 4096);

                    if (ExtractAttributeUniversal(response + boundaries[objIdx].start,
                                                  boundaries[objIdx].end - boundaries[objIdx].start, attributeNames[i],
                                                  attrValue, 4096))
                    {
                        OutputPrintf(&outBuf, "%s: %s\n", attributeNames[i], attrValue);
                    }
                }

                intFree(attrValue);
            }
            else
            {
                OutputPrintf(&outBuf, "\n[No attributes discovered]\n");
            }

            intFree(attributeNames);
        }

        OutputFlush(&outBuf, objIdx);
    }

    intFree(boundaries);

    if (objectsInThisPull)
    {
        *objectsInThisPull = objectCount;
    }

    return TRUE;
}

#endif
