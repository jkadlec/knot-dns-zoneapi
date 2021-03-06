/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*!
 * \file chaos.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \addtogroup query_processing
 * @{
 */

#pragma once

#include <stdlib.h>
#include <stdint.h>

#include "libknot/packet/pkt.h"

/*!
 * \brief Create a response for a given query in the CHAOS class.
 */
int knot_chaos_answer(knot_pkt_t *pkt);

/*! @} */
