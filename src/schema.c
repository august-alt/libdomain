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

#include "schema.h"

struct ldap_schema_t
{
    LDAPObjectClass** object_classes;

    LDAPAttributeType** attribute_types;
};

/*!
 * \brief ldap_schema_new Allocates ldap_schema_t and checks it for validity.
 * \param[in] ctx         TALLOC_CTX to use.
 * \return
 *        - NULL on error.
 *        - Pointer to ldap schema on success.
 */
ldap_schema_t*
ldap_schema_new(TALLOC_CTX *ctx)
{
    if (!ctx)
    {
        error("NULL talloc context.\n");

        return NULL;
    }

    ldap_schema_t* result = talloc_zero(ctx, struct ldap_schema_t);

    if (!result)
    {
        error("Unable to allocate ldap_schema_t.\n");
    }

    return result;
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
ldap_schema_read(ldap_schema_t *schema, const char *file_name)
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

    return RETURN_CODE_SUCCESS;
}

/*!
 * \brief ldap_schema_object_classes Returns a list of LDAPObjectClass structs.
 * \param[in] schema                 Schema to work with.
 * \return
 *        - NULL if schema is NULL.
 *        - List of object classes from schema.
 */
LDAPObjectClass**
ldap_schema_object_classes(const ldap_schema_t *schema)
{
    if (!schema)
    {
        error("Schema is NULL.\n");

        return NULL;
    }

    return schema->object_classes;
}

/*!
 * \brief ldap_schema_attribute_types Returns a list of LDAPAttributeType structs.
 * \param[in] schema                  Schema to work with.
 * \return
 *        - NULL if schema is NULL.
 *        - List of attribute types from schema.
 */
LDAPAttributeType**
ldap_schema_attribute_types(const ldap_schema_t* schema)
{
    if (!schema)
    {
        error("Schema is NULL.\n");

        return NULL;
    }

    return schema->attribute_types;
}
