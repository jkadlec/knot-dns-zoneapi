/*!
 * \file apply.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief Changesets application and update helpers.
 *
 * \addtogroup xfr
 * @{
 */
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

#pragma once

#include <stdint.h>
#include <string.h>

#include "knot/zone/zone.h"
#include "knot/server/xfr-handler.h"
#include "knot/updates/changesets.h"

/*!
 * \brief Checks if a zone transfer is required by comparing the zone's SOA with
 *        the one received from master server.
 *
 * \param zone Zone to check.
 * \param soa_response Response to SOA query received from master server.
 *
 * \retval < 0 if an error occured.
 * \retval 1 if the transfer is needed.
 * \retval 0 if the transfer is not needed.
 */
int xfrin_transfer_needed(const zone_contents_t *zone,
                          knot_pkt_t *soa_response);

/*!
 * \brief Applies changesets *with* zone shallow copy.
 *
 * \param zone          Zone to be updated.
 * \param chsets        Changes to be made.
 * \param new_contents  New zone will be returned using this arg.
 *
 * \return KNOT_E*
 */
int apply_changesets(zone_t *zone, changesets_t *chsets,
                     zone_contents_t **new_contents);

/*!
 * \brief Applies changesets directly to the zone, without copying it.
 *
 * \param contents Zone contents to apply the changesets to. Will be modified.
 * \param chsets   Changesets to be applied to the zone.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL if given one of the arguments is NULL.
 * \return Other error code if the application went wrong.
 */
int apply_changesets_directly(zone_contents_t *contents,
                              changesets_t *chsets);

/*!
 * \brief Cleanups successful update. (IXFR, DNSSEC, DDNS).
 * \param chgs  Changesets used to create the update.
 */
void update_cleanup(changesets_t *chgs);

/*!
 * \brief Rollbacks failed update (IXFR, DNSSEC, DDNS).
 *
 * \param chgs          Changesets used to create the update.
 * \param new_contents  Created zone contents.
 */
void update_rollback(changesets_t *chgs, zone_contents_t **new_contents);

/*!
 * \brief Frees old zone contents - i.e. contents that were used to create the
 *        shallow copy, but are now obsolete.
 * \note Exported because of update.c, zone.c.
 * \param contents  Contents to free.
 */
void update_free_old_zone(zone_contents_t **contents);

/*! @} */
