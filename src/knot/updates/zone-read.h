/*!
 * \file zone_read.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief API for concurrent zone contents reading.
 *
 * \addtogroup server
 * @{
 */
/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/updates/zone-lock.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonedb.h"

typedef struct {
	zone_t *zone;
	zone_lock_t lock;
} zone_read_t;

typedef struct {
#warning redo
	changeset_t ch;
	changeset_iter_t it;
	knot_rrset_t rr;
} zone_rr_iter_t;

typedef struct {
	namedb_txn_t txn;
	namedb_iter_t *it;
} zone_node_iter_t;

int zone_read_begin(zone_read_t *r, const knot_zonedb_t *db, const knot_dname_t *qname);
int zone_read_begin_suffix(zone_read_t *r, knot_zonedb_t *db, const knot_dname_t *qname);
void zone_read_done(zone_read_t *r);

const zone_node_t *zone_read_node_for_type(zone_read_t *zr, const knot_dname_t *owner, const uint16_t type);
const zone_node_t *zone_read_apex(zone_read_t *zr);
const zone_node_t *zone_read_previous_for_type(zone_read_t *zr, const knot_dname_t *owner, const uint16_t type);
const zone_node_t *zone_read_closest_encloser(zone_read_t *zr, const knot_dname_t *owner);

int zone_read_rr_iter(zone_rr_iter_t *it, const zone_read_t *zr, const bool sorted);
int zone_read_node_iter(zone_node_iter_t *it, const zone_read_t *zr, const bool sorted, const bool nsec3);

const zone_node_t *zone_read_iter_next_node(zone_node_iter_t *it);
const knot_rrset_t *zone_read_iter_next_rr(zone_rr_iter_t *it);

void zone_read_node_iter_clear(zone_node_iter_t *it);
void zone_read_rr_iter_clear(zone_rr_iter_t *it);

/*! @} */