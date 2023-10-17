/***********************************************************************************************************************
**
** Copyright (C) 2023 BaseALT Ltd. <org@basealt.ru>
**
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**
***********************************************************************************************************************/
#include "schema_p.h"
#include "schema.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

enum ElementType
{
    LDAP_UNKNOWN_ELEMENT           = 0,
    LDAP_SYNTAX_ELEMENT            = 1,
    LDAP_MATCHING_RULE_ELEMENT     = 2,
    LDAP_MATCHING_RULE_USE_ELEMENT = 3,
    LDAP_ATTRIBUTE_TYPE_ELEMENT    = 4,
    LDAP_OBJECT_CLASS_ELEMENT      = 5,
};

char*
read_line(FILE* file)
{
    char *result = NULL;
    char *line = NULL;
    size_t length = 0;
    ssize_t read = 0;

    bool concatenate = false;  // Flag to indicate if we should concatenate lines

    while ((read = getline(&line, &length, file)) != -1)
    {
        // Remove trailing '\r', '\n', and spaces from the line
        char *end = line + strlen(line) - 1;
        while (end >= line && (*end == '\n' || *end == '\r'))
        {
            *end = '\0';
            end--;
        }

        bool hasNonSpace = false;
        char* current_char = line;
        while (*current_char)
        {
            if (!isspace(*current_char))
            {
                hasNonSpace = true;
                break;
            }
            ++current_char;
        }

        if (hasNonSpace)
        {
            // Concatenate the line to the result
            if (concatenate)
            {
                // Allocate memory for the concatenated line
                char *newResult = (char *)malloc(strlen(result) + strlen(line) + 2); // +2 for space and null terminator
                if (newResult == NULL)
                {
                    perror("Memory allocation error");
                    exit(EXIT_FAILURE);
                }

                int index = 0;
                if (result[strlen(result) - 1] != ' ' && strlen(line) > 2 && line[0] == ' ' && isascii(line[1]))
                {
                    index = 1;
                }

                if (index)
                {
                    sprintf(newResult, "%s%s", result, line + index);
                }
                else
                {
                    sprintf(newResult, "%s\n%s", result, line);
                }
                free(result);
                result = newResult;
            }
            else
            {
                result = strdup(line);
                concatenate = true;
            }
        }
        else
        {
            // Empty line encountered, return the result
            break;
        }
    }

    free(line);
    return result;
}

char*
parse_line(char* line)
{
    if (!line)
    {
        return NULL;
    }

    int index = 0;

    int begin_index = -1;
    int end_index = -1;

    char current_token = line[index];

    while (current_token != '\0')
    {
        char plus_one = line[index + 1];

        switch (current_token)
        {
        case '(':
            if (begin_index == -1)
            {
                begin_index = index;
            }
            break;
        case ')':
            if (plus_one == '\n')
            {
                end_index = index;
            }
            break;
        default:
            break;
        }

        if (begin_index == -1)
        {
            goto update_line;
        }

        if (end_index > begin_index)
        {
            size_t object_size = end_index - begin_index + 1;
            char* result = malloc(object_size + 1);

            strncpy(result, line + begin_index, object_size);
            result[object_size] = '\0';

            return result;
        }

update_line:
        current_token = line[++index];
    }

    return NULL;
}

char*
advance_line(char* line, enum ElementType** type)
{
    int index = 0;

    if (!*type)
    {
        *type = malloc(sizeof(enum ElementType));
    }

    *(*type) = LDAP_UNKNOWN_ELEMENT;

    char current_token = line[index];

    while (current_token != '\0')
    {

        if (strncasecmp(line + index, "ldapsyntax", strlen("ldapsyntax")) == 0 ||
            strncasecmp(line + index, "ldapsyntaxes:", strlen("ldapsyntaxes:")) == 0)
        {
            *(*type) = LDAP_SYNTAX_ELEMENT;

            return line + index;
        }

        if (strncasecmp(line + index, "matchingrule", strlen("matchingrule")) == 0 ||
            strncasecmp(line + index, "matchingrules:", strlen("matchingrules:")) == 0)
        {
            *(*type) = LDAP_MATCHING_RULE_ELEMENT;

            return line + index;
        }

        if (strncasecmp(line + index, "matchingruleuse", strlen("matchingruleuse")) == 0 ||
            strncasecmp(line + index, "matchingruleuse:", strlen("matchingruleuse:")) == 0)
        {
            *(*type) = LDAP_MATCHING_RULE_USE_ELEMENT;

            return line + index;
        }

        if (strncasecmp(line + index, "attributetype", strlen("attributetype")) == 0 ||
            strncasecmp(line + index, "attributetypes:", strlen("attributetypes:")) == 0)
        {
            *(*type) = LDAP_ATTRIBUTE_TYPE_ELEMENT;

            return line + index;
        }

        if (strncasecmp(line + index, "objectclass", strlen("objectclass")) == 0 ||
            strncasecmp(line + index, "objectClasses:", strlen("objectClasses:")) == 0)
        {
            *(*type) = LDAP_OBJECT_CLASS_ELEMENT;

            return line + index;
        }

        current_token = line[++index];
    }

    return NULL;
}

bool register_attributetype(ldap_schema_t *schema, char* line)
{
    LDAPAttributeType *at;
    int code = 0;
    const char *err;

    at = ldap_str2attributetype(line, &code, &err, LDAP_SCHEMA_ALLOW_ALL);

    if (!at)
    {
        error("register_attributetype: AttributeType \"%s\": %s, %s\n", line, ldap_scherr2str(code), err);
        return false;
    }

    if (!ldap_schema_append_attributetype(schema, at))
    {
        error("register_attributetype: Unable to add attribute to schema: %d \n", schema);
        return false;
    }

    char* attribut_str = ldap_attributetype2str(at);

    fprintf(stderr, "Attribute type: %s \n", attribut_str);

    ldap_memfree(attribut_str);
    ldap_attributetype_free(at);

    return true;
}

bool register_objectclass(ldap_schema_t *schema, char* line)
{
    LDAPObjectClass *oc;
    int code = 0;
    const char *err;

    oc = ldap_str2objectclass(line, &code, &err, LDAP_SCHEMA_ALLOW_ALL);

    if (!oc)
    {
        error("register_objectclass: ObjectClass \"%s\": %s, %s\n", line, ldap_scherr2str(code), err);
        return false;
    }

    if (!ldap_schema_append_objectclass(schema, oc))
    {
        error("register_objectclass: Unable to add object class to schema: %d \n", schema);
        return false;
    }

    char* class_str = ldap_objectclass2str(oc);

    fprintf(stderr, "Object class: %s \n", class_str);

    ldap_memfree(class_str);
    ldap_objectclass_free(oc);

    return true;
}

/*!
 * \brief ldap_schema_read Populates ldap_schema_t with object classes and attributes from schema file.
 * \param[inout] schema    Schema to work with.
 * \param[in] file_name    Name of the schema file.
 * \return
 *        - RETURN_CODE_FAILURE on error.
 *        - RETURN_CODE_SUCCESS when parsing schema successful.
 */
enum OperationReturnCode
ldap_schema_read(struct ldap_schema_t *schema, const char *file_name)
{
    if (!schema)
    {
        error("Schema is NULL.\n");

        return RETURN_CODE_FAILURE;
    }

    if (!file_name || strlen(file_name) == 0)
    {
        error("Invalid file name: %s\n", file_name);

        return RETURN_CODE_FAILURE;
    }

    FILE *file = fopen(file_name, "r");
    if (file == NULL)
    {
        error("Failed to open file %s \n", file_name);
        return RETURN_CODE_FAILURE;
    }

    int attribute_count = 0;
    int class_count = 0;

    char *result = NULL;
    while ((result = read_line(file)) != NULL)
    {
        enum ElementType* type = NULL;

        if (result)
        {
            char* line_pointer = advance_line(result, &type);
            char* element = parse_line(line_pointer);

            while (element)
            {
                if (type)
                {
                    switch (*type)
                    {
                    case LDAP_UNKNOWN_ELEMENT:
                    case LDAP_SYNTAX_ELEMENT:
                    case LDAP_MATCHING_RULE_ELEMENT:
                    case LDAP_MATCHING_RULE_USE_ELEMENT:
                        break;
                    case LDAP_ATTRIBUTE_TYPE_ELEMENT:
                        if (register_attributetype(schema, element))
                        {
                            attribute_count++;
                        }
                        break;
                    case LDAP_OBJECT_CLASS_ELEMENT:
                        if (register_objectclass(schema, element))
                        {
                            class_count++;
                        }
                        break;
                    default:
                        fprintf(stderr, "Type corruption!\n");
                        break;
                    }
                }
                else
                {
                    fprintf(stderr, "Type is NULL! \n");
                }

                line_pointer = line_pointer + strlen(element);
                free(element);

                line_pointer = advance_line(line_pointer, &type);
                element = parse_line(line_pointer);
            }

            if (!element)
            {
                fprintf(stderr, "No element found\n");
            }

            free(result);
        }
        else
        {
            fprintf(stderr, "No result found\n");
        }

        if (type)
        {
            free(type);
        }
    }


    fprintf(stderr, "Total attributes registred: %d \n", attribute_count);
    fprintf(stderr, "Total class registred: %d \n", class_count);

    fclose(file);

    return RETURN_CODE_SUCCESS;
}
