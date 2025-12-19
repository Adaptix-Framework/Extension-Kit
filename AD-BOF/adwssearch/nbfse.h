/*
 * nbfse.h - .NET Binary Format: SOAP Encoding
 *
 * Functions for encoding SOAP messages in Microsoft's binary XML format (NBFSE)
 * used by Active Directory Web Services (ADWS) protocol.
 */

#ifndef NBFSE_H
#define NBFSE_H

#ifdef BOF
#include "bofdefs.h"

DECLSPEC_IMPORT RPC_STATUS WINAPI RPCRT4$UuidCreate(UUID *);
#else
#include <rpc.h>
#include <windows.h>
#endif

#define NBFSE_END_ELEMENT 0x01
#define NBFSE_SHORT_ATTRIBUTE 0x04
#define NBFSE_ATTRIBUTE 0x05
#define NBFSE_SHORT_XMLNS_ATTRIBUTE 0x08
#define NBFSE_XMLNS_ATTRIBUTE 0x09
#define NBFSE_DICTIONARY_XMLNS_ATTRIBUTE 0x0B
#define NBFSE_PREFIX_DICTIONARY_ATTRIBUTE_S 0x1E
#define NBFSE_ELEMENT 0x41
#define NBFSE_PREFIX_DICTIONARY_ELEMENT_A 0x44
#define NBFSE_PREFIX_DICTIONARY_ELEMENT_S 0x56
#define NBFSE_BOOL_TEXT_TRUE 0x86
#define NBFSE_CHARS8_TEXT 0x98
#define NBFSE_CHARS8_TEXT_WITH_END_ELEMENT 0x99
#define NBFSE_BYTES8_TEXT 0x9E
#define NBFSE_BYTES8_TEXT_WITH_END_ELEMENT 0x9F
#define NBFSE_DICTIONARY_TEXT 0xAA
#define NBFSE_DICTIONARY_TEXT_WITH_END_ELEMENT 0xAB
#define NBFSE_UNIQUE_ID_TEXT 0xAC

#define DICT_ENVELOPE 0x02
#define DICT_HEADER 0x08
#define DICT_BODY 0x0E
#define DICT_ACTION 0x0A
#define DICT_TO 0x0C
#define DICT_MESSAGEID 0x1A
#define DICT_REPLYTO 0x2C
#define DICT_ADDRESS 0x2A
#define DICT_MUSTUNDERSTAND 0x00

typedef struct
{
    BYTE *data;
    DWORD size;
    DWORD capacity;
} NBFSE_BUFFER;

NBFSE_BUFFER *NBFSEBufferCreate(DWORD initialSize);
void NBFSEBufferFree(NBFSE_BUFFER *buf);
BOOL NBFSEBufferAppend(NBFSE_BUFFER *buf, const BYTE *data, DWORD dataLen);
BOOL NBFSEBufferAppendByte(NBFSE_BUFFER *buf, BYTE b);

BOOL NBFSEWriteMultiByteInt31(NBFSE_BUFFER *buf, DWORD value);
BOOL NBFSEWriteChars8Text(NBFSE_BUFFER *buf, const char *text, BOOL withEndElement);
BOOL NBFSEWriteDictionaryText(NBFSE_BUFFER *buf, BYTE dictId, BOOL withEndElement);
BOOL NBFSEWriteUniqueIdText(NBFSE_BUFFER *buf, const UUID *uuid);
BOOL NBFSEWriteElement(NBFSE_BUFFER *buf, const char *prefix, const char *name);
BOOL NBFSEWriteShortAttribute(NBFSE_BUFFER *buf, const char *name);
BOOL NBFSEWriteXmlnsAttribute(NBFSE_BUFFER *buf, const char *prefix, const char *ns);
BOOL NBFSEWriteDictionaryXmlnsAttribute(NBFSE_BUFFER *buf, const char *prefix, BYTE nsDict);

BOOL BuildEnumerateRequest(NBFSE_BUFFER *buf, const char *ldapFilter, const char *baseDN, const char *targetHost,
                           const char *attrFilter);
BOOL BuildPullRequest(NBFSE_BUFFER *buf, const char *enumContext, DWORD maxElements, const char *targetHost);

NBFSE_BUFFER *NBFSEBufferCreate(DWORD initialSize)
{
    NBFSE_BUFFER *buf = (NBFSE_BUFFER *)intAlloc(sizeof(NBFSE_BUFFER));
    if (!buf)
        return NULL;

    buf->data = (BYTE *)intAlloc(initialSize);
    if (!buf->data)
    {
        intFree(buf);
        return NULL;
    }

    buf->size = 0;
    buf->capacity = initialSize;
    return buf;
}

void NBFSEBufferFree(NBFSE_BUFFER *buf)
{
    if (buf)
    {
        if (buf->data)
            intFree(buf->data);
        intFree(buf);
    }
}

BOOL NBFSEBufferAppend(NBFSE_BUFFER *buf, const BYTE *data, DWORD dataLen)
{
    if (buf->size + dataLen > buf->capacity)
    {
        DWORD newCapacity = buf->capacity * 2;
        while (newCapacity < buf->size + dataLen)
        {
            newCapacity *= 2;
        }

        BYTE *newData = (BYTE *)intAlloc(newCapacity);
        if (!newData)
            return FALSE;

        MSVCRT$memcpy(newData, buf->data, buf->size);
        intFree(buf->data);
        buf->data = newData;
        buf->capacity = newCapacity;
    }

    MSVCRT$memcpy(buf->data + buf->size, data, dataLen);
    buf->size += dataLen;
    return TRUE;
}

BOOL NBFSEBufferAppendByte(NBFSE_BUFFER *buf, BYTE b)
{
    return NBFSEBufferAppend(buf, &b, 1);
}

BOOL NBFSEWriteMultiByteInt31(NBFSE_BUFFER *buf, DWORD value)
{
    if (value < 0x80)
    {
        return NBFSEBufferAppendByte(buf, (BYTE)value);
    }
    else if (value < 0x4000)
    {
        BYTE bytes[2];
        bytes[0] = (BYTE)(0x80 | (value & 0x7F));
        bytes[1] = (BYTE)(value >> 7);
        return NBFSEBufferAppend(buf, bytes, 2);
    }
    else if (value < 0x200000)
    {
        BYTE bytes[3];
        bytes[0] = (BYTE)(0x80 | (value & 0x7F));
        bytes[1] = (BYTE)(0x80 | ((value >> 7) & 0x7F));
        bytes[2] = (BYTE)(value >> 14);
        return NBFSEBufferAppend(buf, bytes, 3);
    }
    else if (value < 0x10000000)
    {
        BYTE bytes[4];
        bytes[0] = (BYTE)(0x80 | (value & 0x7F));
        bytes[1] = (BYTE)(0x80 | ((value >> 7) & 0x7F));
        bytes[2] = (BYTE)(0x80 | ((value >> 14) & 0x7F));
        bytes[3] = (BYTE)(value >> 21);
        return NBFSEBufferAppend(buf, bytes, 4);
    }
    else
    {
        BYTE bytes[5];
        bytes[0] = (BYTE)(0x80 | (value & 0x7F));
        bytes[1] = (BYTE)(0x80 | ((value >> 7) & 0x7F));
        bytes[2] = (BYTE)(0x80 | ((value >> 14) & 0x7F));
        bytes[3] = (BYTE)(0x80 | ((value >> 21) & 0x7F));
        bytes[4] = (BYTE)(value >> 28);
        return NBFSEBufferAppend(buf, bytes, 5);
    }
}

BOOL NBFSEWriteChars8Text(NBFSE_BUFFER *buf, const char *text, BOOL withEndElement)
{
    DWORD len = MSVCRT$strlen(text);
    if (len > 255)
        return FALSE;

    BYTE recordType = withEndElement ? NBFSE_CHARS8_TEXT_WITH_END_ELEMENT : NBFSE_CHARS8_TEXT;
    if (!NBFSEBufferAppendByte(buf, recordType))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, (BYTE)len))
        return FALSE;
    return NBFSEBufferAppend(buf, (const BYTE *)text, len);
}

BOOL NBFSEWriteDictionaryText(NBFSE_BUFFER *buf, BYTE dictId, BOOL withEndElement)
{
    BYTE recordType = withEndElement ? NBFSE_DICTIONARY_TEXT_WITH_END_ELEMENT : NBFSE_DICTIONARY_TEXT;
    if (!NBFSEBufferAppendByte(buf, recordType))
        return FALSE;
    return NBFSEBufferAppendByte(buf, dictId);
}

BOOL NBFSEWriteUniqueIdText(NBFSE_BUFFER *buf, const UUID *uuid)
{
    if (!NBFSEBufferAppendByte(buf, NBFSE_UNIQUE_ID_TEXT))
        return FALSE;
    return NBFSEBufferAppend(buf, (const BYTE *)uuid, 16);
}

BOOL NBFSEWriteElement(NBFSE_BUFFER *buf, const char *prefix, const char *name)
{
    DWORD prefixLen = MSVCRT$strlen(prefix);
    DWORD nameLen = MSVCRT$strlen(name);

    if (!NBFSEBufferAppendByte(buf, NBFSE_ELEMENT))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, (BYTE)prefixLen))
        return FALSE;
    if (!NBFSEBufferAppend(buf, (const BYTE *)prefix, prefixLen))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, (BYTE)nameLen))
        return FALSE;
    return NBFSEBufferAppend(buf, (const BYTE *)name, nameLen);
}

BOOL NBFSEWriteShortAttribute(NBFSE_BUFFER *buf, const char *name)
{
    DWORD nameLen = MSVCRT$strlen(name);

    if (!NBFSEBufferAppendByte(buf, NBFSE_SHORT_ATTRIBUTE))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, (BYTE)nameLen))
        return FALSE;
    return NBFSEBufferAppend(buf, (const BYTE *)name, nameLen);
}

BOOL NBFSEWriteXmlnsAttribute(NBFSE_BUFFER *buf, const char *prefix, const char *ns)
{
    DWORD prefixLen = MSVCRT$strlen(prefix);
    DWORD nsLen = MSVCRT$strlen(ns);

    if (!NBFSEBufferAppendByte(buf, NBFSE_XMLNS_ATTRIBUTE))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, (BYTE)prefixLen))
        return FALSE;
    if (!NBFSEBufferAppend(buf, (const BYTE *)prefix, prefixLen))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, (BYTE)nsLen))
        return FALSE;
    return NBFSEBufferAppend(buf, (const BYTE *)ns, nsLen);
}

BOOL NBFSEWriteDictionaryXmlnsAttribute(NBFSE_BUFFER *buf, const char *prefix, BYTE nsDict)
{
    DWORD prefixLen = MSVCRT$strlen(prefix);

    if (!NBFSEBufferAppendByte(buf, NBFSE_DICTIONARY_XMLNS_ATTRIBUTE))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, (BYTE)prefixLen))
        return FALSE;
    if (!NBFSEBufferAppend(buf, (const BYTE *)prefix, prefixLen))
        return FALSE;
    return NBFSEBufferAppendByte(buf, nsDict);
}

BOOL BuildEnumerateRequest(NBFSE_BUFFER *buf, const char *ldapFilter, const char *baseDN, const char *targetHost, const char *attrFilter)
{
    UUID uuid;

    if (RPCRT4$UuidCreate(&uuid) != RPC_S_OK)
    {
        return FALSE;
    }

    // Empty string table
    if (!NBFSEBufferAppendByte(buf, 0x00))
        return FALSE;

    // <s:Envelope>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_ENVELOPE))
        return FALSE;

    if (!NBFSEWriteDictionaryXmlnsAttribute(buf, "s", 0x04))
        return FALSE;

    if (!NBFSEWriteDictionaryXmlnsAttribute(buf, "a", 0x06))
        return FALSE;

    // xmlns:addata
    if (!NBFSEWriteXmlnsAttribute(buf, "addata", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"))
        return FALSE;

    // xmlns:ad
    if (!NBFSEWriteXmlnsAttribute(buf, "ad", "http://schemas.microsoft.com/2008/1/ActiveDirectory"))
        return FALSE;

    // xmlns:xsd - dictionary 0x374 (encoded as 0xF4 0x06)
    if (!NBFSEBufferAppendByte(buf, NBFSE_DICTIONARY_XMLNS_ATTRIBUTE))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, 0x03))
        return FALSE;
    if (!NBFSEBufferAppend(buf, (const BYTE *)"xsd", 3))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, 0xF4))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, 0x06))
        return FALSE;

    // xmlns:xsi - dictionary 0x372 (encoded as 0xF2 0x06)
    if (!NBFSEBufferAppendByte(buf, NBFSE_DICTIONARY_XMLNS_ATTRIBUTE))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, 0x03))
        return FALSE;
    if (!NBFSEBufferAppend(buf, (const BYTE *)"xsi", 3))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, 0xF2))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, 0x06))
        return FALSE;

    // <s:Header>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_HEADER))
        return FALSE;

    // <a:Action s:mustUnderstand="1">
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_ACTION))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ATTRIBUTE_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_MUSTUNDERSTAND))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_BOOL_TEXT_TRUE))
        return FALSE;

    // Action URL
    if (!NBFSEWriteChars8Text(buf, "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate", TRUE))
        return FALSE;

    // <ad:instance>
    if (!NBFSEWriteElement(buf, "ad", "instance"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "ldap:389", TRUE))
        return FALSE;

    // <a:MessageID>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_MESSAGEID))
        return FALSE;
    if (!NBFSEWriteUniqueIdText(buf, &uuid))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    // <a:ReplyTo>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_REPLYTO))
        return FALSE;

    // <a:Address>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_ADDRESS))
        return FALSE;
    if (!NBFSEWriteDictionaryText(buf, 0x14, TRUE))
        return FALSE;

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    // <a:To s:mustUnderstand="1">
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_TO))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ATTRIBUTE_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_MUSTUNDERSTAND))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_BOOL_TEXT_TRUE))
        return FALSE;

    // Build To URL
    char toUrl[512];
    MSVCRT$sprintf(toUrl, "net.tcp://%s:9389/ActiveDirectoryWebServices/Windows/Enumeration", targetHost);
    if (!NBFSEWriteChars8Text(buf, toUrl, TRUE))
        return FALSE;

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    // <s:Body>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_BODY))
        return FALSE;

    // Move xmlns declarations to Body element (not Envelope)
    // xmlns:wsen
    if (!NBFSEWriteXmlnsAttribute(buf, "wsen", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"))
        return FALSE;

    // xmlns:adlq
    if (!NBFSEWriteXmlnsAttribute(buf, "adlq", "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery"))
        return FALSE;

    // <wsen:Enumerate>
    if (!NBFSEWriteElement(buf, "wsen", "Enumerate"))
        return FALSE;

    if (!NBFSEWriteElement(buf, "wsen", "Filter"))
        return FALSE;
    if (!NBFSEWriteShortAttribute(buf, "Dialect"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/LdapQuery", FALSE))
        return FALSE;

    // <adlq:LdapQuery>
    if (!NBFSEWriteElement(buf, "adlq", "LdapQuery"))
        return FALSE;

    // <adlq:Filter>
    if (!NBFSEWriteElement(buf, "adlq", "Filter"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, ldapFilter, TRUE))
        return FALSE;

    // <adlq:BaseObject>
    if (!NBFSEWriteElement(buf, "adlq", "BaseObject"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, baseDN, TRUE))
        return FALSE;

    // <adlq:Scope>
    if (!NBFSEWriteElement(buf, "adlq", "Scope"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "Subtree", TRUE))
        return FALSE;

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    // Add Selection element if attribute filter is provided (limits what server returns)
    if (attrFilter && MSVCRT$strlen(attrFilter) > 0)
    {
        // <ad:Selection Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">
        if (!NBFSEWriteElement(buf, "ad", "Selection"))
            return FALSE;
        if (!NBFSEWriteShortAttribute(buf, "Dialect"))
            return FALSE;
        if (!NBFSEWriteChars8Text(buf, "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1", FALSE))
            return FALSE;

        // Always add distinguishedName
        // <ad:SelectionProperty>addata:distinguishedname</ad:SelectionProperty>
        if (!NBFSEWriteElement(buf, "ad", "SelectionProperty"))
            return FALSE;
        if (!NBFSEWriteChars8Text(buf, "addata:distinguishedname", TRUE))
            return FALSE;

        // Parse comma-separated attributes and add each one
        char filterCopy[512];
        MSVCRT$strncpy(filterCopy, attrFilter, 511);
        filterCopy[511] = '\0';

        char *token = MSVCRT$strtok(filterCopy, ",");
        while (token != NULL)
        {
            while (*token == ' ')
                token++;

            // <ad:SelectionProperty>addata:attributename</ad:SelectionProperty>
            if (!NBFSEWriteElement(buf, "ad", "SelectionProperty"))
                return FALSE;

            // Build "addata:attributename" string
            char attrName[256];
            MSVCRT$sprintf(attrName, "addata:%s", token);
            if (!NBFSEWriteChars8Text(buf, attrName, TRUE))
                return FALSE;

            token = MSVCRT$strtok(NULL, ",");
        }

        if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
            return FALSE;
    }

    // LDAP control for nTSecurityDescriptor without SACL (needed when getting ALL attributes)
    if (!NBFSEWriteElement(buf, "ad", "controls"))
        return FALSE;

    // <ad:control type="1.2.840.113556.1.4.801" criticality="true">
    if (!NBFSEWriteElement(buf, "ad", "control"))
        return FALSE;
    if (!NBFSEWriteShortAttribute(buf, "type"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "1.2.840.113556.1.4.801", FALSE))
        return FALSE;
    if (!NBFSEWriteShortAttribute(buf, "criticality"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "true", FALSE))
        return FALSE;

    // <ad:controlValue>MAMCAQc=</ad:controlValue>
    if (!NBFSEWriteElement(buf, "ad", "controlValue"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "MAMCAQc=", TRUE))
        return FALSE; // Base64 of 30 03 02 01 07

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    return TRUE;
}

BOOL BuildPullRequest(NBFSE_BUFFER *buf, const char *enumContext, DWORD maxElements, const char *targetHost)
{
    // Empty string table
    if (!NBFSEBufferAppendByte(buf, 0x00))
        return FALSE;

    // <s:Envelope>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_ENVELOPE))
        return FALSE;

    // xmlns:s
    if (!NBFSEWriteDictionaryXmlnsAttribute(buf, "s", 0x04))
        return FALSE;

    // xmlns:a
    if (!NBFSEWriteDictionaryXmlnsAttribute(buf, "a", 0x06))
        return FALSE;

    // xmlns:ad
    if (!NBFSEWriteXmlnsAttribute(buf, "ad", "http://schemas.microsoft.com/2008/1/ActiveDirectory"))
        return FALSE;

    UUID uuid;
    if (RPCRT4$UuidCreate(&uuid) != RPC_S_OK)
    {
        return FALSE;
    }

    // <s:Header>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_HEADER))
        return FALSE;

    // <a:Action s:mustUnderstand="1">
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_ACTION))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ATTRIBUTE_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_MUSTUNDERSTAND))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_BOOL_TEXT_TRUE))
        return FALSE;

    // Action URL
    if (!NBFSEWriteChars8Text(buf, "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull", TRUE))
        return FALSE;

    // <a:MessageID>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_MESSAGEID))
        return FALSE;
    if (!NBFSEWriteUniqueIdText(buf, &uuid))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    // <a:ReplyTo>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_REPLYTO))
        return FALSE;

    // <a:Address>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_ADDRESS))
        return FALSE;
    if (!NBFSEWriteDictionaryText(buf, 0x14, TRUE))
        return FALSE;

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    // <a:To s:mustUnderstand="1">
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_A))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_TO))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ATTRIBUTE_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_MUSTUNDERSTAND))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_BOOL_TEXT_TRUE))
        return FALSE;

    char toUrl[512];
    MSVCRT$sprintf(toUrl, "net.tcp://%s:9389/ActiveDirectoryWebServices/Windows/Enumeration", targetHost);
    if (!NBFSEWriteChars8Text(buf, toUrl, TRUE))
        return FALSE;

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    // <s:Body>
    if (!NBFSEBufferAppendByte(buf, NBFSE_PREFIX_DICTIONARY_ELEMENT_S))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, DICT_BODY))
        return FALSE;

    // xmlns:wsen
    if (!NBFSEWriteXmlnsAttribute(buf, "wsen", "http://schemas.xmlsoap.org/ws/2004/09/enumeration"))
        return FALSE;

    // <wsen:Pull>
    if (!NBFSEWriteElement(buf, "wsen", "Pull"))
        return FALSE;

    // <wsen:EnumerationContext>
    if (!NBFSEWriteElement(buf, "wsen", "EnumerationContext"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, enumContext, TRUE))
        return FALSE;

    // <wsen:MaxElements>
    if (!NBFSEWriteElement(buf, "wsen", "MaxElements"))
        return FALSE;
    char maxElemStr[32];
    MSVCRT$sprintf(maxElemStr, "%d", maxElements);
    if (!NBFSEWriteChars8Text(buf, maxElemStr, TRUE))
        return FALSE;

    // LDAP control - always added to get security descriptor
    if (!NBFSEWriteElement(buf, "ad", "controls"))
        return FALSE;

    // <ad:control type="1.2.840.113556.1.4.801" criticality="true">
    if (!NBFSEWriteElement(buf, "ad", "control"))
        return FALSE;
    if (!NBFSEWriteShortAttribute(buf, "type"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "1.2.840.113556.1.4.801", FALSE))
        return FALSE;
    if (!NBFSEWriteShortAttribute(buf, "criticality"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "true", FALSE))
        return FALSE;

    // <ad:controlValue>
    if (!NBFSEWriteElement(buf, "ad", "controlValue"))
        return FALSE;
    if (!NBFSEWriteChars8Text(buf, "MAMCAQc=", TRUE))
        return FALSE; // Base64 of 30 03 02 01 07

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;
    if (!NBFSEBufferAppendByte(buf, NBFSE_END_ELEMENT))
        return FALSE;

    return TRUE;
}

#endif
