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
#ifndef LIBDOMAIN_LSM_H
#define LIBDOMAIN_LSM_H

#include "connection.h"

enum LibraryState
{
    LIBDOMAIN_STATE_NONE             = 0,
    LIBDOMAIN_STATE_INIT             = 1,
    LIBDOMAIN_STATE_DETECT_DIRECTORY = 2,
    LIBDOMAIN_STATE_READ_SCHEMA      = 3,
    LIBDOMAIN_STATE_READY            = 4,
    LIBDOMAIN_STATE_ERROR            = 5,
};

typedef struct lsm_ctx_t lsm_ctx_t;

enum LibraryState lsm_init(struct lsm_ctx_t* ctx, struct ldap_connection_ctx_t *connection);
enum LibraryState lsm_next_state(struct lsm_ctx_t* ctx);
enum LibraryState lsm_set_state(struct lsm_ctx_t* ctx, enum LibraryState state);

#endif//LIBDOMAIN_LSM_H
